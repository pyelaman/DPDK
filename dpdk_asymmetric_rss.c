#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <signal.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_rcu_qsbr.h>
#include <rte_malloc.h>
#include <rte_cycles.h>

#define BURST_SIZE 32
#define MAX_FLOWS 1048576
#define PREFETCH_OFFSET 4

static volatile bool force_quit = false;

// 5-Tuple Key Structure
struct flow_key_5tuple {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;
    uint8_t  pad;
} __attribute__((packed));

// Stateful Flow Value Entry
typedef struct {
    uint64_t packet_count;
    uint64_t byte_count;
    uint16_t egress_port;
    uint16_t forward_queue;
    uint16_t reverse_queue;
} flow_entry_t;

// Global Shared Context
struct global_context {
    struct rte_hash *flow_table;
    struct rte_rcu_qsbr *rcu_v;
    struct rte_mempool *mbuf_pool;
};

struct global_context g_ctx;

// Signal Handler
static void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\nSignal %d caught, terminating execution context...\n", signum);
        force_quit = true;
    }
}

// PILLAR 1 & 4: CONFIGURING PORT WITH ASYMMETRIC RSS ENABLED
static inline int port_init(uint16_t port, struct rte_mempool *mbuf_pool, uint16_t nr_queues) {
    // Custom Symmetric Toeplitz Hash Key to mitigate asymmetric RSS differences 
    // If hardware doesn't support symmetric sorting, our LF-Hash handles the cross-core hits
    //      .rss_conf = {
    //            .rss_key = symmetric_rss_key,
    //            .rss_key_len = 40,
    //            .rss_hf = RTE_ETH_RSS_IP | RTE_ETH_RSS_UDP | RTE_ETH_RSS_TCP,
    //        },
    static uint8_t symmetric_rss_key[40] = {
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
        0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A
    };

    struct rte_eth_conf port_conf = {
        .rxmode = {
            .mq_mode = RTE_ETH_MQ_RX_RSS,
        },
        .rx_adv_conf = {
            .rss_conf = {
                .rss_key = NULL,
                .rss_key_len = 0,
                .rss_hf = RTE_ETH_RSS_IP | RTE_ETH_RSS_UDP | RTE_ETH_RSS_TCP,
            },
        },
    };

    int retval;
    uint16_t q;

    if (!rte_eth_dev_is_valid_port(port)) return -1;

    struct rte_eth_dev_info dev_info;
    int ret = rte_eth_dev_info_get(port, &dev_info);
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

    // Now this will succeed on your Realtek NIC!
    ret = rte_eth_dev_configure(port, nr_queues, nr_queues, &port_conf);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n", ret, port);
    }

    for (q = 0; q < nr_queues; q++) {
        retval = rte_eth_rx_queue_setup(port, q, 128, rte_eth_dev_socket_id(port), NULL, mbuf_pool);
        if (retval < 0) return retval;
        retval = rte_eth_tx_queue_setup(port, q, 128, rte_eth_dev_socket_id(port), NULL);
        if (retval < 0) return retval;
    }

    retval = rte_eth_dev_start(port);
    if (retval < 0) return retval;

    rte_eth_promiscuous_enable(port);
    return 0;
}

// PILLAR 2 & 3: THE LOCK-FREE RUN-TO-COMPLETION CORE PIPELINE
static int lcore_worker_loop(void *arg) {
    struct global_context *ctx = (struct global_context *)arg;
    unsigned int lcore_id = rte_lcore_id();
    uint16_t queue_id = (uint16_t)rte_lcore_index(lcore_id - 1); // Map RSS queue relative to core array index

    printf("[LCORE-%u] Running data plane loop on Ingress RX Queue %u\n", lcore_id, queue_id);

    // Register this thread to the Quiescent State Based Reclamation timeline
    rte_rcu_qsbr_thread_register(ctx->rcu_v, lcore_id);
    rte_rcu_qsbr_thread_online(ctx->rcu_v, lcore_id);

    struct rte_mbuf *pkts_burst[BURST_SIZE];

    while (!force_quit) {
        // Poll assigned RSS hardware queue
        uint16_t nb_rx = rte_eth_rx_burst(0, queue_id, pkts_burst, BURST_SIZE);
        
        if (unlikely(nb_rx == 0)) {
            // QUIESCENT STATE: Core is idling, safe for control plane to execute pruning updates
            rte_rcu_qsbr_quiescent(ctx->rcu_v, lcore_id);
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
                    
                    flow_keys[i].src_ip   = ip_hdr->src_addr;
                    flow_keys[i].dst_ip   = ip_hdr->dst_addr;
                    flow_keys[i].src_port = tcp_hdr->src_port;
                    flow_keys[i].dst_port = tcp_hdr->dst_port;
                    flow_keys[i].proto    = ip_hdr->next_proto_id;
                    
                    keys[i] = &flow_keys[i];
		    valid_packet_count++;
                    continue;
                }
            }
            keys[i] = NULL;
        }

        // SIMD Bulk Cuckoo Match. LF Concurrency ensures safe multi-thread reads
	if (valid_packet_count > 0) {
             rte_hash_lookup_bulk_data(ctx->flow_table, keys, nb_rx, &hit_mask, entries);
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
                
                // Use atomic updates if counter structures are shared across asymmetric RSS paths
                __atomic_fetch_add(&state->packet_count, 1, __ATOMIC_RELAXED);
                __atomic_fetch_add(&state->byte_count, rte_pktmbuf_data_len(m), __ATOMIC_RELAXED);

                rte_eth_tx_burst(state->egress_port, queue_id, &m, 1);
            } else {
                // SLOW-PATH CACHE MISS (Asymmetric Discovery Phase)
                // Initialize state entry visible globally to all queues immediately
                flow_entry_t *new_entry = rte_zmalloc("flow_entry", sizeof(flow_entry_t), RTE_CACHE_LINE_SIZE);
                if (new_entry) {
                    new_entry->egress_port = 0;
                    new_entry->packet_count = 1;
                    new_entry->byte_count = rte_pktmbuf_data_len(m);
                    new_entry->forward_queue = queue_id; 
                    new_entry->reverse_queue = 0xFFFF; // Discovered on reverse traffic hit

                    // Thread-safe lockless addition on the fly
                    rte_hash_add_key_data(ctx->flow_table, &flow_keys[i], (void *)new_entry);
                }
                rte_eth_tx_burst(0, queue_id, &m, 1);
            }
        }

        // QUIESCENT STATE: Completed active burst processing boundary
        rte_rcu_qsbr_quiescent(ctx->rcu_v, lcore_id);
    }

    rte_rcu_qsbr_thread_offline(ctx->rcu_v, lcore_id);
    rte_rcu_qsbr_thread_unregister(ctx->rcu_v, lcore_id);
    return 0;
}

int main(int argc, char *argv[]) {
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    uint16_t nb_lcores = rte_lcore_count();
    if (nb_lcores < 2) rte_exit(EXIT_FAILURE, "Minimum 2 lcores required for lab topology\n");

    // Initialize Memory Pools
    g_ctx.mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", 8191 * nb_lcores, 256, 0, 
                                              RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!g_ctx.mbuf_pool) rte_exit(EXIT_FAILURE, "Cannot initialize mbuf pool\n");

    // Initialize Concurrency-Safe Lock-Free Cuckoo Hash Table
    struct rte_hash_parameters hash_params = {
        .name = "asymmetric_flow_table",
        .entries = MAX_FLOWS,
        .key_len = sizeof(struct flow_key_5tuple),
        .hash_func = rte_jhash,
        .hash_func_init_val = 0,
        .socket_id = rte_socket_id(),
        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF | RTE_HASH_EXTRA_FLAGS_MULTI_WRITER_ADD
    };

    g_ctx.flow_table = rte_hash_create(&hash_params);
    if (!g_ctx.flow_table) rte_exit(EXIT_FAILURE, "Cannot create flow table matrix\n");

    // Initialize RCU QSBR Engine
    size_t rcu_sz = rte_rcu_qsbr_get_memsize(RTE_MAX_LCORE);
    g_ctx.rcu_v = rte_zmalloc("rcu_qsbr", rcu_sz, RTE_CACHE_LINE_SIZE);
    rte_rcu_qsbr_init(g_ctx.rcu_v, RTE_MAX_LCORE);

    struct rte_hash_rcu_config rcu_cfg = {
        .v = g_ctx.rcu_v,
        .mode = RTE_HASH_QSBR_MODE_DQ,
        .free_key_data_func = (void (*)(void *, void *))rte_free,
    };
    rte_hash_rcu_qsbr_add(g_ctx.flow_table, &rcu_cfg);

    // Initialize Port 0 with matched multi-queues mapped to worker lcores
    if (port_init(0, g_ctx.mbuf_pool, 1) != 0) { // 3rd arg: nb_lcores - 1
        rte_exit(EXIT_FAILURE, "Cannot initialize network port 0\n");
    }

    // Launch run-to-completion pipelines on all registered workers
    unsigned int lcore_id;
    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        rte_eal_remote_launch(lcore_worker_loop, &g_ctx, lcore_id);
    }

    // Master lcore acts as the Control Plane management layer
    while (!force_quit) {
        rte_delay_ms(1000);
        // In a live system, the control plane can safely traverse the table here via
        // rte_hash_iterate() and call rte_hash_del_key() to prune expired flows.
    }

    rte_eal_mp_wait_lcore();
    //rte_eth_dev_stop(port_id);
    //rte_eth_dev_close(port_id);
    //rte_hash_free(flow_table);
    //rte_free(qsv);
    printf("[+] Data plane offline successfully.\n");
    return 0;
}
