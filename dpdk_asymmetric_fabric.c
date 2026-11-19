#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_hash.h>
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

// Pillar 1 Struct: Flow signature layout
struct flow_key_5tuple {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;
    uint8_t  pad;
} __attribute__((packed));

// Application state tracker bound to the fast-path telemetry lines
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
    uint16_t queue_id = (uint16_t)rte_lcore_index(lcore_id - 1);

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
        } else {
	    printf("Received %d packets.\n", nb_rx);
	}

        const void *keys[BURST_SIZE];
        struct flow_key_5tuple flow_keys[BURST_SIZE];
        void *entries[BURST_SIZE];
        uint64_t hit_mask = 0;
	uint32_t valid_packet_count = 0;

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
		    valid_packet_count++;
                    continue;
                }
            }
            keys[i] = NULL; 
        }

        // SIMD Parallel Hash Query
	if (valid_packet_count > 0) {
             rte_hash_lookup_bulk_data(flow_table, keys, nb_rx, &hit_mask, entries);
	} else {
	     printf("No IPv4 packets found.\n");
	}

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

    struct rte_eth_dev_info dev_info;
    int ret = rte_eth_dev_info_get(port_id, &dev_info);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Error during getting device info: %s\n", strerror(-ret));
    }

    // 🛠️ FIX: Check if the NIC actually supports RSS
    if (dev_info.flow_type_rss_offloads == 0) {
        printf("Notice: Hardware does not support RSS. Disabling RSS offloads.\n");

        // Completely disable RSS multi-queue mode and clear the hash functions
        port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;
        port_conf.rx_adv_conf.rss_conf.rss_hf = 0;
    } else {
        // If it supports RSS, safely trim your requested hash functions to match what the NIC supports
        port_conf.rx_adv_conf.rss_conf.rss_hf &= dev_info.flow_type_rss_offloads;
    }

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
        rte_eal_remote_launch(dpdk_worker_lcore_entry, &ctx, lcore);
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

