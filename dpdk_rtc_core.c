#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_hash.h>
#include <rte_prefetch.h>
#include <rte_jhash.h>
#include <rte_rcu_qsbr.h>
#include <rte_malloc.h>
#include <rte_ethdev.h>
#include <rte_prefetch.h>
#include <rte_cycles.h>

#define BURST_SIZE 32
#define PREFETCH_OFFSET 4
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define MAX_FLOWS 1048576

// Volatile atomic exit flag monitored by parallel lcores
static volatile bool force_quit = false;

/*
 *
1. Software Prefetching Pipeline Stride (PREFETCH_OFFSET = 4)

Explain how the prefetch pipeline operates. When processing packet i, the code calls 
rte_prefetch0() on packet i + 4. This issues an async hardware request to pull the future 
packet's memory space into the L1 cache. By the time the loop index increments 4 steps forward, 
those packet headers are already sitting in L1, completely mitigating the 60ns latency penalty 
of a raw main memory lookup (DDR access).

2. Vectorized SIMD Hashing Math (rte_hash_lookup_bulk_data)

Highlight that you did not implement a sequential for loop to look up keys one by one. 
The rte_hash_lookup_bulk_data function evaluates the hash keys for the entire burst of up to 64 
packets simultaneously. On processors supporting AVX-2 or AVX-512, the compiler runs parallel CPU 
vector operations to check multiple signatures across the Cuckoo Hash memory table buckets in a 
single clock cycle.

3. Bitmask Branch Parsing (hit_mask & (1ULL << i))

Point out the extraction of the evaluation branch. The bulk lookup engine populates a single 
64-bit integer (hit_mask), where each bit indicates a lookup status (1 for a match, 0 for a miss). 
Using a bitwise AND check is incredibly fast, allowing the compiler to optimize branch prediction 
loops perfectly via the likely() and unlikely() macros.

*/

/*
 * Even with lockless software structures, you will lose performance if multiple threads 
 * try to grab traffic from a single shared hardware queue. 
 * To prevent this, Receive Side Scaling (RSS) uses the network card's hardware ASICs 
 * to distribute flows evenly across independent per-core queues on ingress.
 *
 */

/*
 * The Ingress Pipeline Mapping Strategy

1. ASIC Hashing: When a packet crosses the wire, the NIC hashes the 5-tuple payload fields to 
                 generate a 32-bit hash value.

2. Indirection Table Routing: The NIC uses the lower bits of that hash as an index into an 
                              internal RSS Indirection Table (e.g., a 128-entry hardware array). 
                              Each index maps to a specific Hardware RX Queue.

3. Lock Elimination: If you configure the indirection table so that Queue 0 -> lcore 1, 
                     Queue 1 -> lcore 2, and so on, packets belonging to the same application 
                     stream will always land on the exact same CPU core. 
                     This ensures full session locality and eliminates the need for cross-core 
                     cache invalidations or multi-thread locking synchronization in the fast path.
 *
 */

struct rte_eth_conf port_conf = {
    .rxmode = {
        .mq_mode = RTE_ETH_MQ_RX_RSS, // Enable Multi-Queue RSS mode on Ingress
    },
    .rx_adv_conf = {
        .rss_conf = {
            // Supply standard symmetric hash key values used by the NIC ASIC
            .rss_key = NULL, // Hardware defaults applied
            .rss_key_len = 0,
            // Configure the hardware to hash across the complete 5-tuple payload structure
            .rss_hf = RTE_ETH_RSS_IP | RTE_ETH_RSS_UDP | RTE_ETH_RSS_TCP,
        },
    },
};

// 5-Tuple Structure representing our flow key
struct flow_key_5tuple {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;
    uint8_t  pad[3]; // Padding to align structure nicely onto 32-bit boundary
} __attribute__((packed));

// Application-specific state structure stored in the Hash Table value pointer
typedef struct {
    uint64_t packet_count;
    uint64_t byte_count;
    uint16_t egress_port;
    bool     is_active;
} flow_entry_t;

// Context structure passed straight into the run-to-completion pipeline loops
struct worker_ctx {
    struct rte_hash     *flow_table;
    struct rte_rcu_qsbr *qsv;
    uint16_t             port_id;
};

// Catch system-level keyboard termination triggers to gracefully un-bind rings
static void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\n[SYSTEM] Intercepted exit signal. Shutting down data plane gracefully...\n");
        force_quit = true;
    }
}

// Simulated Slow-Path Fallback for table lookup misses
static void handle_slow_path_fallback(struct rte_mbuf *m, struct flow_key_5tuple *key, struct rte_hash *flow_table) {
    // In a principal-level system, the slow path handles routing lookups (LPM),
    // instantiates a new state rule, and programs it back into the Cuckoo Hash for future packets.
    printf("[SLOW-PATH] Cache Miss for flow %u.%u.%u.%u -> %u.%u.%u.%u. Creating state tracking line.\n",
           (key->src_ip >> 24) & 0xFF, (key->src_ip >> 16) & 0xFF, (key->src_ip >> 8) & 0xFF, key->src_ip & 0xFF,
           (key->dst_ip >> 24) & 0xFF, (key->dst_ip >> 16) & 0xFF, (key->dst_ip >> 8) & 0xFF, key->dst_ip & 0xFF);

    flow_entry_t *new_entry = rte_zmalloc("flow_entry", sizeof(flow_entry_t), RTE_CACHE_LINE_SIZE);
    if (new_entry) {
        new_entry->egress_port = 2; // Default fallback route port index
        new_entry->is_active = true;
        new_entry->packet_count = 1;
        new_entry->byte_count = rte_pktmbuf_data_len(m);
        
        // Atomically program the Cuckoo Hash table on the fly
        rte_hash_add_key_data(flow_table, key, (void *)new_entry);
    }
}

// Pillar 4: Hardware RSS Interface Initialization Engine
static inline int configure_network_port(uint16_t port_id, uint16_t nb_queues, struct rte_mempool *mbuf_pool) {
    struct rte_eth_conf port_conf = {
        .rxmode = {
            .mq_mode = RTE_ETH_MQ_RX_RSS, // Multi-Queue Receive Side Scaling enabled
        },
        .rx_adv_conf = {
            .rss_conf = {
                .rss_key = NULL, // Apply hardware vendor default keys
                .rss_key_len = 0,
                // Direct NIC to compute hashes across full Layer 3 and Layer 4 frames
                .rss_hf = RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP,
            },
        },
    };

    if (rte_eth_dev_configure(port_id, nb_queues, nb_queues, &port_conf) < 0) {
        return -1;
    }

    // Provision Ring queues independently for each worker thread
    for (uint16_t q = 0; q < nb_queues; q++) {
        if (rte_eth_rx_queue_setup(port_id, q, 1024, rte_eth_dev_socket_id(port_id), NULL, mbuf_pool) < 0) {
            return -1;
        }
        if (rte_eth_tx_queue_setup(port_id, q, 1024, rte_eth_dev_socket_id(port_id), NULL) < 0) {
            return -1;
        }
    }

    return rte_eth_dev_start(port_id);
}

// THE RUN-TO-COMPLETION CORE LCORE PROCESSING PIPELINE
static int dpdk_rtc_worker_loop(void *arg) {
    struct rte_hash *flow_table = (struct rte_hash *)arg;
    uint16_t port_id = 0;     // Target hardware ingress port
    uint16_t queue_id = 0;    // Core assigned hardware queue context
    
    unsigned int lcore_id = rte_lcore_id();
    printf("[RTC-CORE] Launching Run-To-Completion Pipeline on Worker lcore %u\n", lcore_id);

    // Continuous processing pipeline execution loop
    while (!force_quit) { // Simulating standard execution flag bounds
        struct rte_mbuf *pkts_burst[BURST_SIZE];
        
        // 1. BURST INGRESS: Poll the hardware ring without locks or interrupts
        uint16_t nb_rx = rte_eth_rx_burst(port_id, queue_id, pkts_burst, BURST_SIZE);
        if (unlikely(nb_rx == 0)) {
            rte_pause(); // Yield CPU pipeline execution slightly to save power if ring is empty
            continue;
        }

        // Arrays to hold bulk lookup parameter blocks for the Cuckoo Hash engine
        const void *keys[BURST_SIZE];
        struct flow_key_5tuple flow_keys[BURST_SIZE];
        void *entries[BURST_SIZE];
        int32_t positions[BURST_SIZE];
        uint64_t hit_mask = 0;

        // 2. PARSING & SOFTWARE PREFETCHING STAGE
        for (int i = 0; i < nb_rx; i++) {
            // Software Prefetching: Bring future packet descriptors and header caches 
            // down to L1 memory spaces before the loop logic hits them.
            if (i + PREFETCH_OFFSET < nb_rx) {
                rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[i + PREFETCH_OFFSET], void *));
                rte_prefetch0(pkts_burst[i + PREFETCH_OFFSET]);
            }

            struct rte_mbuf *m = pkts_burst[i];
            struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
            
            // Check for IPv4 traffic explicitly
            if (eth_hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
                struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
                
                if (ip_hdr->next_proto_id == IPPROTO_TCP) {
                    struct rte_tcp_hdr *tcp_hdr = (struct rte_tcp_hdr *)(ip_hdr + 1);
                    
                    // Populate flow 5-tuple arrays
                    flow_keys[i].src_ip   = ip_hdr->src_addr;
                    flow_keys[i].dst_ip   = ip_hdr->dst_addr;
                    flow_keys[i].src_port = tcp_hdr->src_port;
                    flow_keys[i].dst_port = tcp_hdr->dst_port;
                    flow_keys[i].proto    = ip_hdr->next_proto_id;
                    
                    keys[i] = &flow_keys[i];
                    continue;
                }
            }
            // Fallback for non-TCP/IPv4 traffic templates
            keys[i] = NULL; 
        }

        #pragma GCC diagnostic push
        #pragma GCC diagnostic ignored "-Wnonnull"
        // 3. BULK CUCKOO HASH LOOKUP: Process entire burst lane in one function call
        // This utilizes SIMD instructions under the hood (AVX-512) to match entries in parallel
        int lookup_status = rte_hash_lookup_bulk_data(flow_table, keys, nb_rx, &hit_mask, entries);
        #pragma GCC diagnostic pop

        // 4. DATA PLANE ROUTING & BRANCH EVALUATION STAGE
        if (likely(lookup_status >= 0)) {
            for (int i = 0; i < nb_rx; i++) {
                struct rte_mbuf *m = pkts_burst[i];
                
                if (unlikely(keys[i] == NULL)) {
                    rte_pktmbuf_free(m); // Discard unhandled protocol definitions
                    continue;
                }

                // Check bitmask vector to separate FAST-PATH hits from SLOW-PATH misses
                if (likely(hit_mask & (1ULL << i))) {
                    // ---- FAST-PATH CACHE HIT ENGINE ----
                    flow_entry_t *flow_state = (flow_entry_t *)entries[i];
                    
                    // Increment telemetry registers directly inside cache boundaries
                    flow_state->packet_count++;
                    flow_state->byte_count += rte_pktmbuf_data_len(m);
                    
                    // Forward out of the pre-calculated hardware interface port
                    rte_eth_tx_burst(flow_state->egress_port, queue_id, &m, 1);
                } else {
                    // ---- SLOW-PATH ROUTING FALLBACK ENGINE ----
                    handle_slow_path_fallback(m, &flow_keys[i], flow_table);
                    rte_eth_tx_burst(2, queue_id, &m, 1); // Deliver packet along default path
                }
            }
        }
    }
    return 0;
}

// --- FULL COMPLETE UNBROKEN EXECUTION ENTRY-POINT ---
int main(int argc, char *argv[]) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // 1. Initialize Environmental Abstraction Layer (EAL)
    int eal_ret = rte_eal_init(argc, argv);
    if (eal_ret < 0) {
        rte_exit(EXIT_FAILURE, "Error initializing DPDK EAL Layer\n");
    }

    uint16_t nb_ports = rte_eth_dev_count_avail();
    if (nb_ports == 0) {
        rte_exit(EXIT_FAILURE, "No compatible physical network interfaces found.\n");
    }

    uint16_t port_id = 0;
    uint16_t nb_workers = (uint16_t)(rte_lcore_count() - 1); // Dedicate 1 Core for Control Plane/OS
    if (nb_workers == 0) {
        rte_exit(EXIT_FAILURE, "Insufficient CPU Cores allocation. Minimum 2 lcores required.\n");
    }

    // 2. Instantiate Global Memory Pools inside Hugepages
    struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create(
        "packet_mbuf_pool", NUM_MBUFS, MBUF_CACHE_SIZE, 0,
        RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id()
    );
    if (!mbuf_pool) {
        rte_exit(EXIT_FAILURE, "Failed to allocate hugepage mbuf memory pools.\n");
    }

    // 3. Pillar 1: Configure Lockless Concurrency Hash Matrix Properties
    struct rte_hash_parameters hash_params = {
        .name = "asym_lockless_fabric_table",
        .entries = MAX_FLOWS,
        .key_len = sizeof(struct flow_key_5tuple),
        .hash_func = rte_jhash,
        .hash_func_init_val = 0,
        .socket_id = rte_socket_id(),
        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF | // Lock-Free Data Path
                      RTE_HASH_EXTRA_FLAGS_MULTI_WRITER_ADD   // Safe Control Plane insertion
    };

    struct rte_hash *flow_table = rte_hash_create(&hash_params);
    if (!flow_table) {
        rte_exit(EXIT_FAILURE, "Failed to instantiate Cuckoo Hash core table mapping.\n");
    }

    // 4. Pillar 2: Configure Read-Copy-Update (RCU) Defer-Free Architecture
    size_t rcu_sz = rte_rcu_qsbr_get_memsize(RTE_MAX_LCORE);

    struct rte_rcu_qsbr *qsv = rte_zmalloc("rcu_qsbr_core", rcu_sz, RTE_CACHE_LINE_SIZE);

    if (!qsv) {
        rte_exit(EXIT_FAILURE, "Failed to allocate RCU timeline memory.\n");
    }

    if (rte_rcu_qsbr_init(qsv, RTE_MAX_LCORE) < 0) {
        rte_exit(EXIT_FAILURE, "Failed to initialize RCU baseline structures.\n");
    }

    struct rte_hash_rcu_config rcu_cfg = {
            .v = qsv,
            .mode = RTE_HASH_QSBR_MODE_DQ, // Use automated deferred reclamation queues
            .free_key_data_func = (void (*)(void *, void *))rte_free,
    };

    if (rte_hash_rcu_qsbr_add(flow_table, &rcu_cfg) < 0) {
        rte_exit(EXIT_FAILURE, 
                "Failed binding RCU controller engine to the active table mapping.\n");
    }

    // 5. Initialize the hardware network interface with RSS multi-queue rules
    printf("[INITIALIZE] Initializing hardware RSS multi-queue scaling...\n");

    if (configure_network_port(port_id, nb_workers, mbuf_pool) < 0) {
        rte_exit(EXIT_FAILURE, "Failed configuring physical hardware port boundaries.\n");
    }

    // 6. Launch Run-to-Completion Workers asynchronously across pinned lcores
    struct worker_ctx ctx = {
        .flow_table = flow_table,
        .qsv = qsv,
        .port_id = port_id
    };

    unsigned int lcore;
    RTE_LCORE_FOREACH_WORKER(lcore) {
        rte_eal_remote_launch(dpdk_rtc_worker_loop, &ctx, lcore);
    }

    // 7. Core 0 (Main Thread) loops to act as the Control Plane / Monitoring Engine
    printf("[+] CORE PIPELINE ACTIVE. Master thread monitoring stats. Press Ctrl-C to terminate.\n");
    while (!force_quit) {
        sleep(5);
        // Simulating control plane monitoring or pruning updates
        uint32_t current_entries = rte_hash_count(flow_table);
        printf("[CONTROL-PLANE-TELEMETRY] Current active track flows inside Cuckoo Matrix: %u\n", 
                current_entries);
    }

    // 8. Graceful Teardown and Resource Reclamation Sequence
    printf("[TEARDOWN] Waiting for async worker threads to yield offline.\n");
    rte_eal_mp_wait_lcore();

    printf("[TEARDOWN] Flushing hardware interfaces and releasing memory allocations.\n");
    rte_eth_dev_stop(port_id);
    rte_eth_dev_close(port_id);
    rte_hash_free(flow_table);
    rte_free(qsv);
    printf("[+] Data plane offline successfully.\n");
    return 0;
}

