#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <rte_common.h>
#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_rcu_qsbr.h>
#include <rte_malloc.h>
#include <rte_prefetch.h>
#include <rte_cycles.h>

#define BURST_SIZE 32
#define MAX_FLOWS 1048576
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define PREFETCH_OFFSET 4

static volatile bool force_quit = false;
struct rte_hash *global_flow_table = NULL;
struct rte_rcu_qsbr *global_rcu_qsv = NULL;

// Pillar 1 & 4: 5-Tuple Structure with symmetrical comparison markers
struct flow_key_5tuple {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;
    uint8_t  pad;
} __attribute__((packed));

typedef struct {
    uint64_t packet_count;
    uint64_t byte_count;
    uint16_t egress_port;
    uint32_t is_active;
} flow_entry_t;

// Context structure passed straight into the run-to-completion pipeline loops
struct worker_ctx {
    struct rte_hash     *flow_table;
    struct rte_rcu_qsbr *qsv;
    uint16_t             port_id;
};

// Signal handler to exit loops gracefully 
static void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\n[SIGNAL] Intercepted shutdown request. Tearing down cores...\n");
        force_quit = true;
    }
}

// Intercept asymmetric reverse flows and normalize their structures for unified tracking
static inline void get_canonical_flow_key(struct rte_ipv4_hdr *ip_hdr, struct rte_tcp_hdr *tcp_hdr, struct flow_key_5tuple *key) {
    if (ip_hdr->src_addr < ip_hdr->dst_addr) {
        key->src_ip   = ip_hdr->src_addr;
        key->dst_ip   = ip_hdr->dst_addr;
        key->src_port = tcp_hdr->src_port;
        key->dst_port = tcp_hdr->dst_port;
    } else {
        // ASYMMETRIC REVERSAL: Invert keys so both directions hit the exact same state entry
        key->src_ip   = ip_hdr->dst_addr;
        key->dst_ip   = ip_hdr->src_addr;
        key->src_port = tcp_hdr->dst_port;
        key->dst_port = tcp_hdr->src_port;
    }
    key->proto = ip_hdr->next_proto_id;
    key->pad   = 0;
}

// Pillar 3: Fast-Path Core Loop with RCU Quiescent State checkpoints
static int dpdk_worker_lcore_entry(void *arg) {
    struct worker_ctx *ctx = (struct worker_ctx *)arg;
    struct rte_hash *flow_table = ctx->flow_table;
    struct rte_rcu_qsbr *qsv = ctx->qsv;
    uint16_t port_id = ctx->port_id;
    
    unsigned int lcore_id = rte_lcore_id();
    uint16_t queue_id = (uint16_t)rte_lcore_index(lcore_id);

    printf("[FAST-PATH] Core %u Polling Port %u, RX Queue %u\n", lcore_id, port_id, queue_id);

    // Register this thread with the shared RCU context timeline
    rte_rcu_qsbr_thread_register(qsv, lcore_id);
    rte_rcu_qsbr_thread_online(qsv, lcore_id);

    while (!force_quit) {
        struct rte_mbuf *pkts_burst[BURST_SIZE];
        uint16_t nb_rx = rte_eth_rx_burst(port_id, queue_id, pkts_burst, BURST_SIZE);
        
        if (unlikely(nb_rx == 0)) {
            // QUIESCENT CHECKPOINT: Core is idle; safe for Control Plane to prune entries
            rte_rcu_qsbr_quiescent(qsv, lcore_id);
            continue;
        }

        const void *keys[BURST_SIZE];
        struct flow_key_5tuple flow_keys[BURST_SIZE];
        void *entries[BURST_SIZE];
        uint64_t hit_mask = 0;

        for (int i = 0; i < nb_rx; i++) {
            if (i + PREFETCH_OFFSET < nb_rx) {
                rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[i + PREFETCH_OFFSET], void *));
                rte_prefetch0(pkts_burst[i + PREFETCH_OFFSET]);
            }

            struct rte_mbuf *m = pkts_burst[i];
            struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
            
            if (eth_hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
                struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
                if (ip_hdr->next_proto_id == IPPROTO_TCP) {
                    struct rte_tcp_hdr *tcp_hdr = (struct rte_tcp_hdr *)(ip_hdr + 1);
                    
                    // Generate normalized, asymmetry-safe hash key signatures
                    get_canonical_flow_key(ip_hdr, tcp_hdr, &flow_keys[i]);
                    keys[i] = &flow_keys[i];
                    continue;
                }
            }
            keys[i] = NULL; 
        }

        // SIMD Parallel Hash Query
        rte_hash_lookup_bulk_data(flow_table, keys, nb_rx, &hit_mask, entries);

        for (int i = 0; i < nb_rx; i++) {
            struct rte_mbuf *m = pkts_burst[i];
            if (unlikely(keys[i] == NULL)) {
                rte_pktmbuf_free(m);
                continue;
            }

            if (likely(hit_mask & (1ULL << i))) {
                // FAST-PATH CACHE HIT
                flow_entry_t *state = (flow_entry_t *)entries[i];
                state->packet_count++;
                state->byte_count += rte_pktmbuf_data_len(m);
                
                // Swap MAC addresses for standard echo-forward loopback
                struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
                struct rte_ether_addr tmp = eth->dst_addr;
                eth->dst_addr = eth->src_addr;
                eth->src_addr = tmp;

                rte_eth_tx_burst(port_id, queue_id, &m, 1);
            } else {
                // FAST-PATH MISS: Allocate state rule live without lock blocks
                flow_entry_t *new_entry = rte_zmalloc("flow_state", sizeof(flow_entry_t), RTE_CACHE_LINE_SIZE);
                if (new_entry) {
                    new_entry->is_active = true;
                    new_entry->packet_count = 1;
                    new_entry->byte_count = rte_pktmbuf_data_len(m);
                    new_entry->egress_port = port_id;
                    
                    // Add key atomically to the running Cuckoo hash table
                    rte_hash_add_key_data(flow_table, &flow_keys[i], (void *)new_entry);
                }
                rte_pktmbuf_free(m);
            }
        }
        // QUIESCENT CHECKPOINT: Completed processing cycle loop safely
        rte_rcu_qsbr_quiescent(qsv, lcore_id);
    }

    rte_rcu_qsbr_thread_offline(qsv, lcore_id);
    rte_rcu_qsbr_thread_unregister(qsv, lcore_id);
    return 0;
}

// Pillar 4: Symmetrical Key Derivation to solve asymmetric RSS lane splits
static inline void get_symmetrical_key(const struct flow_key_5tuple *orig, struct flow_key_5tuple *sym) {
    if (orig->src_ip < orig->dst_ip) {
        sym->src_ip   = orig->src_ip;
        sym->dst_ip   = orig->dst_ip;
        sym->src_port = orig->src_port;
        sym->dst_port = orig->dst_port;
    } else if (orig->src_ip > orig->dst_ip) {
        sym->src_ip   = orig->dst_ip;
        sym->dst_ip   = orig->src_ip;
        sym->src_port = orig->dst_port;
        sym->dst_port = orig->src_port;
    } else {
        // Tie breaker if IPs match (evaluate port index boundaries)
        sym->src_ip = orig->src_ip;
        sym->dst_ip = orig->dst_ip;
        if (orig->src_port <= orig->dst_port) {
            sym->src_port = orig->src_port;
            sym->dst_port = orig->dst_port;
        } else {
            sym->src_port = orig->dst_port;
            sym->dst_port = orig->src_port;
        }
    }
    sym->proto = orig->proto;
    sym->pad   = 0;
}

// Pillar 1: Initializing Lock-Free Multi-Writer Architecture
struct rte_hash *create_concurrency_safe_flow_table(uint32_t max_entries) {
    struct rte_hash_parameters params = {
        .name = "lf_rss_flow_table",
        .entries = max_entries,
        .key_len = sizeof(struct flow_key_5tuple),
        .hash_func = rte_jhash,
        .hash_func_init_val = 0,
        .socket_id = rte_socket_id(),
        // Enable Lock-Free Readers and Multi-Writer additions concurrently
        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF | 
                      RTE_HASH_EXTRA_FLAGS_MULTI_WRITER_ADD
    };

    struct rte_hash *hash_handle = rte_hash_create(&params);
    if (!hash_handle) return NULL;

    size_t rcu_sz = rte_rcu_qsbr_get_memsize(RTE_MAX_LCORE);
    global_rcu_qsv = rte_zmalloc("rcu_qsbr", rcu_sz, RTE_CACHE_LINE_SIZE);
    if (!global_rcu_qsv) {
        rte_hash_free(hash_handle);
        return NULL;
    }

    struct rte_hash_rcu_config rcu_cfg = {
        .v = global_rcu_qsv,
        .mode = RTE_HASH_QSBR_MODE_DQ, // Deferred reclamation via internal queue
        .free_key_data_func = (void (*)(void *, void *))rte_free,
    };

    if (rte_hash_rcu_qsbr_add(hash_handle, &rcu_cfg) < 0) {
        rte_free(global_rcu_qsv);
        rte_hash_free(hash_handle);
        return NULL;
    }

    return hash_handle;
}

// Pillar 2 & 4: Lockless Core Processing Loop with Symmetrical RSS handling
static int worker_lcore_loop(__rte_unused void *arg) {
    unsigned int lcore_id = rte_lcore_id();
    uint16_t port_id = 0;
    
    // Register lcore context with the system QSBR RCU grid timeline
    rte_rcu_qsbr_thread_register(global_rcu_qsv, lcore_id);
    rte_rcu_qsbr_thread_online(global_rcu_qsv, lcore_id);

    printf("[CORE-FASTPATH] Core %u online and polling RX Queue %u\n", lcore_id, lcore_id);

    while (!force_quit) {
        struct rte_mbuf *pkts_burst[BURST_SIZE];
        // Poll hardware queues using clean RSS core isolation map limits
        uint16_t nb_rx = rte_eth_rx_burst(port_id, lcore_id, pkts_burst, BURST_SIZE);
        
        if (unlikely(nb_rx == 0)) {
            // Report Quiescent state during idles so control plane can safely prune memory entries
            rte_rcu_qsbr_quiescent(global_rcu_qsv, lcore_id);
            continue;
        }

        const void *keys[BURST_SIZE];
        struct flow_key_5tuple raw_keys[BURST_SIZE];
        struct flow_key_5tuple sym_keys[BURST_SIZE];
        void *entries[BURST_SIZE];
        uint64_t hit_mask = 0;

        for (int i = 0; i < nb_rx; i++) {
            if (i + PREFETCH_OFFSET < nb_rx) {
                rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[i + PREFETCH_OFFSET], void *));
                rte_prefetch0(pkts_burst[i + PREFETCH_OFFSET]);
            }

            struct rte_mbuf *m = pkts_burst[i];
            struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
            
            if (eth_hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
                struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
                if (ip_hdr->next_proto_id == IPPROTO_TCP) {
                    struct rte_tcp_hdr *tcp_hdr = (struct rte_tcp_hdr *)(ip_hdr + 1);
                    
                    raw_keys[i].src_ip   = ip_hdr->src_addr;
                    raw_keys[i].dst_ip   = ip_hdr->dst_addr;
                    raw_keys[i].src_port = tcp_hdr->src_port;
                    raw_keys[i].dst_port = tcp_hdr->dst_port;
                    raw_keys[i].proto    = ip_hdr->next_proto_id;

                    // ASYMMETRIC REDIRECTION RESOLUTION: Force lookups onto a unified symmetrical signature map
                    get_symmetrical_key(&raw_keys[i], &sym_keys[i]);
                    keys[i] = &sym_keys[i];
                    continue;
                }
            }
            keys[i] = NULL;
        }

        #pragma GCC diagnostic push
        #pragma GCC diagnostic ignored "-Wnonnull"
        // Bulk SIMD Cuckoo Parallel Lookup
        rte_hash_lookup_bulk_data(global_flow_table, keys, nb_rx, &hit_mask, entries);
        #pragma GCC diagnostic pop

        for (int i = 0; i < nb_rx; i++) {
            struct rte_mbuf *m = pkts_burst[i];
            if (unlikely(keys[i] == NULL)) {
                rte_pktmbuf_free(m);
                continue;
            }

            if (likely(hit_mask & (1ULL << i))) {
                // Fast-Path hit execution lane
                flow_entry_t *state = (flow_entry_t *)entries[i];
                __atomic_fetch_add(&state->packet_count, 1, __ATOMIC_RELAXED);
                __atomic_fetch_add(&state->byte_count, rte_pktmbuf_data_len(m), __ATOMIC_RELAXED);
                
                // Transmit packet out of the assigned interface index port
                rte_eth_tx_burst(state->egress_port, lcore_id, &m, 1);
            } else {
                // Slow-Path cache miss fallback execution lane
                flow_entry_t *new_flow = rte_zmalloc("flow", sizeof(flow_entry_t), RTE_CACHE_LINE_SIZE);
                if (new_flow) {
                    new_flow->egress_port = port_id ^ 1; // Direct trace down paired interface route
                    new_flow->packet_count = 1;
                    new_flow->byte_count = rte_pktmbuf_data_len(m);
                    
                    // Concurrency-safe atomic key addition on the fly
                    rte_hash_add_key_data(global_flow_table, keys[i], (void *)new_flow);
                }
                rte_eth_tx_burst(port_id ^ 1, lcore_id, &m, 1);
            }
        }

        // Report cycle milestone complete to enable safe control-plane garbage collection
        rte_rcu_qsbr_quiescent(global_rcu_qsv, lcore_id);
    }

    rte_rcu_qsbr_thread_offline(global_rcu_qsv, lcore_id);
    rte_rcu_qsbr_thread_unregister(global_rcu_qsv, lcore_id);
    return 0;
}

// Pillar 4: RSS Multi-Queue Device Configuration Environment Wrapper
static inline int configure_network_port(uint16_t port_id, uint16_t num_queues, struct rte_mempool *mp) {
    struct rte_eth_conf port_conf = {
        .rxmode = { .mq_mode = RTE_ETH_MQ_RX_RSS }, // Force Receive Side Scaling Hardware ASICs
        .rx_adv_conf = {
            .rss_conf = {
                .rss_key = NULL, // Apply physical NIC default keys
                .rss_hf = RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP // Hash over 4-tuple variables
            }
        }
    };

    if (rte_eth_dev_configure(port_id, num_queues, num_queues, &port_conf) < 0) return -1;

    for (uint16_t q = 0; q < num_queues; q++) {
        if (rte_eth_rx_queue_setup(port_id, q, 1024, rte_eth_dev_socket_id(port_id), NULL, mp) < 0) return -1;
        if (rte_eth_tx_queue_setup(port_id, q, 1024, rte_eth_dev_socket_id(port_id), NULL) < 0) return -1;
    }

    return rte_eth_dev_start(port_id);
}

int main(int argc, char **argv) {
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_exit(EXIT_FAILURE, "Error initializing EAL context.\n");

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    uint16_t num_cores = rte_lcore_count();
    struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS, 
                                                            MBUF_CACHE_SIZE, 0, 
                                                            RTE_MBUF_DEFAULT_BUF_SIZE, 
                                                            rte_socket_id());
    if (!mbuf_pool) rte_exit(EXIT_FAILURE, "Failed to allocate memory pool caches.\n");

    // 1. Pillar 1: Configure Lockless Concurrency Hash Matrix Properties
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

    // 2. Pillar 2: Configure Read-Copy-Update (RCU) Defer-Free Architecture
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
        rte_exit(EXIT_FAILURE, "Failed binding RCU controller engine to the active table mapping.\n");
    }

    // 3. Initialize the hardware network interface with RSS multi-queue rules
    uint16_t port_id = 0;
    uint16_t nb_workers = (uint16_t)(num_cores - 1); // Dedicate 1 Core for Control Plane/OS
    if (nb_workers == 0) {
        rte_exit(EXIT_FAILURE, "Insufficient CPU Cores allocation. Minimum 2 lcores required.\n");
    }

    printf("[INITIALIZE] Initializing network infrastructure with hardware RSS multi-queue scaling...\n");
    if (configure_network_port(port_id, nb_workers, mbuf_pool) < 0) {
        rte_exit(EXIT_FAILURE, "Failed configuring physical hardware port boundaries.\n");
    }

    // 4. Launch Run-to-Completion Workers asynchronously across pinned lcores
    struct worker_ctx ctx = {
        .flow_table = flow_table,
        .qsv = qsv,
        .port_id = port_id
    };

    unsigned int lcore;
    RTE_LCORE_FOREACH_WORKER(lcore) {
        rte_eal_remote_launch(dpdk_worker_lcore_entry, &ctx, lcore);
    }

    // 5. Core 0 (Main Thread) loops to act as the Control Plane / Monitoring Engine
    printf("[+] CORE PIPELINE ACTIVE. Master thread monitoring statistics. Press Ctrl-C to terminate.\n");
    while (!force_quit) {
        sleep(5);

        // Simulating control plane monitoring or pruning updates
        uint32_t current_entries = rte_hash_count(flow_table);
        printf("[CONTROL-PLANE-TELEMETRY] Current active track flows inside Cuckoo Matrix: %u\n", current_entries);
    }

    // 6. Graceful Teardown and Resource Reclamation Sequence
    printf("[TEARDOWN] Waiting for async worker threads to yield offline...\n");
    rte_eal_mp_wait_lcore();

    printf("[TEARDOWN] Flushing hardware interfaces and releasing memory allocations...\n");
    rte_eth_dev_stop(port_id);
    rte_eth_dev_close(port_id);
    rte_hash_free(flow_table);
    rte_free(qsv);

    printf("[+] Data plane offline successfully.\n");
    return 0;
}
