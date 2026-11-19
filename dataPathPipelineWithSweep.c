#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_cycles.h>
#include <rte_mbuf.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_acl.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_ether.h>
#include <rte_mempool.h>

#include "dataplane_structs.h"

#define BURST_SIZE 32
#define SECONDS_TO_CYCLES(s) ((s) * rte_get_tsc_hz())
#define FLOW_TIMEOUT_LIMIT_SEC 5

/* Thread Synchronization Flag */
volatile uint8_t force_quit = 0;

/* Global Tables and Pools */
struct rte_hash *fast_path_hash_table = NULL;
struct rte_acl_ctx *slow_path_acl_ctx = NULL;
struct rte_mempool *flow_entry_mempool = NULL;
struct rte_mempool *pkt_mbuf_pool = NULL;

static void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\nSignal %d intercepted. Graceful shutdown sequence initiated...\n", signum);
        force_quit = 1;
    }
}

/* Helper function to extract 5-tuple from raw packet buffer memory */
static inline int extract_5tuple(struct rte_mbuf *m, struct flow_key *key) {
    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    if (eth_hdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) return -1;

    struct rte_ipv4_hdr *ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
    key->src_ip = ipv4_hdr->src_addr;
    key->dst_ip = ipv4_hdr->dst_addr;
    key->proto  = ipv4_hdr->next_proto_id;

    if (key->proto == IPPROTO_TCP) {
        struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(ipv4_hdr + 1);
        key->src_port = tcp->src_port;
        key->dst_port = tcp->dst_port;
    } else {
        key->src_port = 0; key->dst_port = 0;
    }
    return 0;
}

/* ================== ENTRY POINT A: THE DATA PATH PIPELINE ================== */
static int
run_dataplane_worker(void *arg) {
    uint16_t queue_id = 0;
    struct rte_mbuf *pkts[BURST_SIZE];
    printf("[Core %u] Data Plane Worker active. Simulating line-rate processing...\n", rte_lcore_id());

    while (!force_quit) {
        /* In an active deployment, you would call: rte_eth_rx_burst(port, queue_id, pkts, BURST_SIZE);
         * For our isolated test sandbox, we simulate packets processing out of our local pool */
        uint16_t nb_rx = 1; 
        if (rte_pktmbuf_alloc_bulk(pkt_mbuf_pool, pkts, nb_rx) < 0) continue;

        /* Write a mock packet header hitting our tracking filters */
        struct rte_ether_hdr *eth = rte_pktmbuf_mtod(pkts[0], struct rte_ether_hdr *);
        eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
        struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
        ip->next_proto_id = IPPROTO_TCP;
        ip->src_addr = RTE_IPV4(10, 0, 0, 7);
        ip->dst_addr = RTE_IPV4(192, 168, 1, 1);
        struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(ip + 1);
        tcp->src_port = rte_cpu_to_be_16(5543);
        tcp->dst_port = rte_cpu_to_be_16(80);
        pkts[0]->pkt_len = 64; pkts[0]->data_len = 64;

        struct flow_key keys[BURST_SIZE];
        const void *key_ptrs[BURST_SIZE];
        void *flow_data[BURST_SIZE] = {NULL};
        uint64_t hit_mask = 0;

        extract_5tuple(pkts[0], &keys[0]);
        key_ptrs[0] = &keys[0];

        /* Query the fast path */
        rte_hash_lookup_bulk_data(fast_path_hash_table, key_ptrs, nb_rx, &hit_mask, flow_data);

        if (hit_mask & 1) {
            struct flow_entry *entry = (struct flow_entry *)flow_data[0];
            entry->total_packets++;
            /* ATOMIC EXTENSION: Update timestamp register locklessly using the core's local clock */
            entry->last_active_timestamp = rte_rdtsc();
        } else {
            /* Cache Miss - Create a new session entry */
            struct flow_entry *new_entry;
            if (rte_mempool_get(flow_entry_mempool, (void **)&new_entry) == 0) {
                new_entry->key = keys[0];
                new_entry->verdict = VERDICT_FORWARD;
                new_entry->last_active_timestamp = rte_rdtsc(); // Set early birth clock
                
                if (rte_hash_add_key_data(fast_path_hash_table, &keys[0], new_entry) < 0) {
                    rte_mempool_put(flow_entry_mempool, new_entry);
                } else {
                    printf("[Data Path Core] New flow cached in Cuckoo Table.\n");
                }
            }
        }

        rte_pktmbuf_free(pkts[0]);
        rte_delay_ms(500); // Throttled to 500ms loops so you can visually parse the logs
    }
    return 0;
}

/* ================== ENTRY POINT B: THE LOCKLESS SWEEPER THREAD ================== */
static int
run_garbage_collector(void *arg) {
    const void *key;
    void *data;
    uint32_t iter = 0;
    int32_t position;
    uint64_t timeout_cycles = SECONDS_TO_CYCLES(FLOW_TIMEOUT_LIMIT_SEC);
    
    printf("[Core %u] Lockless Flow Garbage Collector sweeper active.\n", rte_lcore_id());

    while (!force_quit) {
        uint64_t current_cycles = rte_rdtsc();
        if (iter >= 1024) iter = 0;

        for (int batch = 0; batch < 32; batch++) {
            position = rte_hash_iterate(fast_path_hash_table, &key, &data, &iter);
            if (position == -ENOENT) {
                iter = 0;
                break;
            }

            struct flow_entry *entry = (struct flow_entry *)data;
            if (entry != NULL) {
                /* Evaluate elapsed time delta locklessly */
                if ((current_cycles - entry->last_active_timestamp) > timeout_cycles) {
                    /* Evict from fast path hash map */
                    rte_hash_del_key(fast_path_hash_table, key);
                    /* Recycle memory block back into the centralized matrix allocator */
                    rte_mempool_put(flow_entry_mempool, entry);
                    printf("[Sweeper Core] Evicted stale, inactive NAT flow from table successfully.\n");
                }
            }
        }
        rte_delay_ms(1000); // Check session age once per second
    }
    return 0;
}

/* ================== CORE COORDINATOR CONTROL PLANE ================== */
int main(int argc, char *argv[]) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    int ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_exit(EXIT_FAILURE, "EAL initialization failed\n");

    /* Confirm user passed down enough isolated computational cores to run both paths */
    if (rte_lcore_count() < 3) {
        rte_exit(EXIT_FAILURE, "Error: This multi-core setup requires at least 3 logical cores (-l 1,2,3)\n");
    }

    /* Initialize Supporting Memory Pools */
    pkt_mbuf_pool = rte_pktmbuf_pool_create("PKT_POOL", 128, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    flow_entry_mempool = rte_mempool_create("ENTRY_POOL", 256, sizeof(struct flow_entry), 0, 0, NULL, NULL, NULL, NULL, rte_socket_id(), 0);
    
    struct rte_hash_parameters hash_params = {
        .name = "INTEGRATED_FLOW_TABLE",
        .entries = 1024,
        .key_len = sizeof(struct flow_key),
        .hash_func = rte_jhash,
        .hash_func_init_val = 0,
        .socket_id = (int)rte_socket_id()
    };
    fast_path_hash_table = rte_hash_create(&hash_params);
    if (!pkt_mbuf_pool || !flow_entry_mempool || !fast_path_hash_table) {
        rte_exit(EXIT_FAILURE, "Global memory map configuration collapsed.\n");
    }

    /* Identify and Map Core Layout Allocations */
    unsigned int main_core = rte_get_main_lcore();
    unsigned int data_core = rte_get_next_lcore(main_core, 0, 0);
    unsigned int sweep_core = rte_get_next_lcore(data_core, 0, 0);

    /* Launch Worker Pipelines on separate designated silicon channels */
    rte_eal_remote_launch(run_dataplane_worker, NULL, data_core);
    rte_eal_remote_launch(run_garbage_collector, NULL, sweep_core);

    /* Main Core steps back into tracking role, waiting for user termination */
    printf("[Main Core %u] Control Plane active. Pipelined system initialized.\n", main_core);
    rte_eal_mp_wait_lcore();

    /* Clean Up Tables and Memory Segments on Exit */
    rte_hash_free(fast_path_hash_table);
    printf("Workspace discharged cleanly. Execution terminated.\n");
    return 0;
}

