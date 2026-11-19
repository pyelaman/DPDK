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
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_ether.h>
#include <rte_mempool.h>

#include "dataplane_structs.h"

#define BURST_SIZE 32
#define SECONDS_TO_CYCLES(s) ((s) * rte_get_tsc_hz())

volatile uint8_t force_quit = 0;

/* Global Tables and Pools */
struct rte_hash *fast_path_hash_table = NULL;
struct rte_mempool *flow_entry_mempool = NULL;
struct rte_mempool *pkt_mbuf_pool = NULL;

static void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\nSignal %d intercepted. Graceful shutdown sequence initiated...\n", signum);
        force_quit = 1;
    }
}

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

/* Inline TCP Stateful Firewall Transition Logic */
static inline void
process_tcp_state_machine(struct flow_entry *entry, struct rte_tcp_hdr *tcp_hdr, int is_client_packet) {
    uint8_t flags = tcp_hdr->tcp_flags;
    uint32_t seq_num = rte_be_to_cpu_32(tcp_hdr->sent_seq);

    if (unlikely(flags & RTE_TCP_RST_FLAG)) {
        entry->state = TCP_STATE_CLOSED;
        entry->verdict = VERDICT_DROP;
        printf("[State Engine] TCP RST seen ➔ State forced to CLOSED\n");
        return;
    }

    switch (entry->state) {
        case TCP_STATE_NONE:
            if (flags == RTE_TCP_SYN_FLAG) {
                entry->state = TCP_STATE_SYN_SENT;
                entry->client_next_seq = seq_num + 1;
                entry->verdict = VERDICT_FORWARD;
                printf("[State Engine] TCP SYN seen ➔ State updated to SYN_SENT\n");
            } else {
                entry->verdict = VERDICT_DROP;
            }
            break;

        case TCP_STATE_SYN_SENT:
            if (!is_client_packet && (flags == (RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG))) {
                entry->state = TCP_STATE_SYN_RECEIVED;
                entry->server_next_seq = seq_num + 1;
                printf("[State Engine] TCP SYN-ACK seen ➔ State updated to SYN_RECEIVED\n");
            }
            break;

        case TCP_STATE_SYN_RECEIVED:
            if (is_client_packet && (flags & RTE_TCP_ACK_FLAG)) {
                entry->state = TCP_STATE_ESTABLISHED;
                printf("[State Engine] TCP Handshake Complete ➔ Circuit ESTABLISHED\n");
            }
            break;

        case TCP_STATE_ESTABLISHED:
            if (flags & RTE_TCP_FIN_FLAG) {
                entry->state = TCP_STATE_FIN_WAIT;
                printf("[State Engine] TCP FIN teardown request initiated ➔ FIN_WAIT\n");
            }
            break;

        case TCP_STATE_FIN_WAIT:
            if (flags & RTE_TCP_ACK_FLAG) {
                entry->state = TCP_STATE_CLOSED;
                printf("[State Engine] Connection Terminated cleanly ➔ State updated to CLOSED\n");
            }
            break;

        case TCP_STATE_CLOSED:
            entry->verdict = VERDICT_DROP;
            break;
    }
}

/* ================== UPDATED DATA PLANE WORKER (CORE 2) ================== */
static int
run_dataplane_worker(void *arg) {
    struct rte_mbuf *pkts[BURST_SIZE];
    printf("[Core %u] Data Plane Worker active. Processing dynamic handshake streams...\n", rte_lcore_id());

    uint32_t iteration = 0;

    while (!force_quit) {
        uint16_t nb_rx = 1; 
        if (rte_pktmbuf_alloc_bulk(pkt_mbuf_pool, pkts, nb_rx) < 0) continue;

        struct rte_ether_hdr *eth = rte_pktmbuf_mtod(pkts[0], struct rte_ether_hdr *);
        eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
        struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
        ip->next_proto_id = IPPROTO_TCP;
        struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(ip + 1);
        
        int is_client_packet = 1;

        /* Simulate a step-by-step 3-way handshake and tear-down sequence across iterations */
        if (iteration == 0) {
            ip->src_addr = RTE_IPV4(10, 0, 0, 7);     ip->dst_addr = RTE_IPV4(192, 168, 1, 1);
            tcp->src_port = rte_cpu_to_be_16(5543);   tcp->dst_port = rte_cpu_to_be_16(80);
            tcp->tcp_flags = RTE_TCP_SYN_FLAG;
        } else if (iteration == 1) {
            /* Server Responding back (Symmetric RSS means this maps to the same core) */
            ip->src_addr = RTE_IPV4(192, 168, 1, 1);  ip->dst_addr = RTE_IPV4(10, 0, 0, 7);
            tcp->src_port = rte_cpu_to_be_16(80);     tcp->dst_port = rte_cpu_to_be_16(5543);
            tcp->tcp_flags = RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG;
            is_client_packet = 0;
        } else if (iteration == 2) {
            ip->src_addr = RTE_IPV4(10, 0, 0, 7);     ip->dst_addr = RTE_IPV4(192, 168, 1, 1);
            tcp->src_port = rte_cpu_to_be_16(5543);   tcp->dst_port = rte_cpu_to_be_16(80);
            tcp->tcp_flags = RTE_TCP_ACK_FLAG;
        } else if (iteration == 3) {
            ip->src_addr = RTE_IPV4(10, 0, 0, 7);     ip->dst_addr = RTE_IPV4(192, 168, 1, 1);
            tcp->src_port = rte_cpu_to_be_16(5543);   tcp->dst_port = rte_cpu_to_be_16(80);
            tcp->tcp_flags = RTE_TCP_FIN_FLAG;
        } else if (iteration == 4) {
            ip->src_addr = RTE_IPV4(192, 168, 1, 1);  ip->dst_addr = RTE_IPV4(10, 0, 0, 7);
            tcp->src_port = rte_cpu_to_be_16(80);     tcp->dst_port = rte_cpu_to_be_16(5543);
            tcp->tcp_flags = RTE_TCP_ACK_FLAG;
            is_client_packet = 0;
        } else {
            /* Keep emitting idle packets to prevent thread spinning lockups */
            ip->src_addr = RTE_IPV4(10, 0, 0, 7);     ip->dst_addr = RTE_IPV4(192, 168, 1, 1);
            tcp->src_port = rte_cpu_to_be_16(5543);   tcp->dst_port = rte_cpu_to_be_16(80);
            tcp->tcp_flags = RTE_TCP_ACK_FLAG;
        }
        pkts[0]->pkt_len = 64; pkts[0]->data_len = 64;

        struct flow_key key;
        struct flow_key lookup_key;
        extract_5tuple(pkts[0], &key);

        /* To find directional state records accurately, normalize lookup to look for client signatures */
        if (!is_client_packet) {
            lookup_key.src_ip = key.dst_ip;    lookup_key.dst_ip = key.src_ip;
            lookup_key.src_port = key.dst_port; lookup_key.dst_port = key.src_port;
            lookup_key.proto = key.proto;
        } else {
            lookup_key = key;
        }

        void *flow_data = NULL;
        uint64_t hit_mask = 0;
        const void *key_ptr = &lookup_key;

        rte_hash_lookup_bulk_data(fast_path_hash_table, &key_ptr, 1, &hit_mask, &flow_data);

        struct flow_entry *entry = (struct flow_entry *)flow_data;

        if (hit_mask & 1) {
            entry->total_packets++;
            entry->last_active_timestamp = rte_rdtsc();
            process_tcp_state_machine(entry, tcp, is_client_packet);
        } else if (is_client_packet && tcp->tcp_flags == RTE_TCP_SYN_FLAG) {
            /* Create new tracking context boundary only if initial packet is a valid SYN */
            struct flow_entry *new_entry;
            if (rte_mempool_get(flow_entry_mempool, (void **)&new_entry) == 0) {
                memset(new_entry, 0, sizeof(struct flow_entry));
                new_entry->key = lookup_key;
                new_entry->state = TCP_STATE_NONE;
                new_entry->last_active_timestamp = rte_rdtsc();
                
                process_tcp_state_machine(new_entry, tcp, is_client_packet);
                
                if (rte_hash_add_key_data(fast_path_hash_table, &lookup_key, new_entry) < 0) {
                    rte_mempool_put(flow_entry_mempool, new_entry);
                }
            }
        }

        rte_pktmbuf_free(pkts[0]);
        iteration++;
        rte_delay_ms(1000); // Step through cycles precisely every 1000ms
    }
    return 0;
}

/* ================== UPDATED ADAPTIVE SWEEPER (CORE 3) ================== */
static int
run_garbage_collector(void *arg) {
    const void *key;
    void *data;
    uint32_t iter = 0;
    int32_t position;
    
    printf("[Core %u] Stateful Adaptive Garbage Collector active.\n", rte_lcore_id());

    while (!force_quit) {
        uint64_t current_cycles = rte_rdtsc();
        if (iter >= 1024) iter = 0;

        position = rte_hash_iterate(fast_path_hash_table, &key, &data, &iter);
        if (position >= 0 && data != NULL) {
            struct flow_entry *entry = (struct flow_entry *)data;
            uint64_t idle_cycles = current_cycles - entry->last_active_timestamp;

            int should_evict = 0;

            /* ATOMIC EXTENSION: Apply distinct adaptive timeout ceilings based on active tracking state */
            if (entry->state == TCP_STATE_CLOSED) {
                should_evict = 1;
                printf("[Sweeper Core] Immediate Eviction ➔ TCP connection reached CLOSED boundary.\n");
            } else if (entry->state == TCP_STATE_SYN_SENT && idle_cycles > SECONDS_TO_CYCLES(3)) {
                should_evict = 1;
                printf("[Sweeper Core] Defense Eviction ➔ Half-Open connection timed out (Possible SYN Flood).\n");
            } else if (entry->state == TCP_STATE_ESTABLISHED && idle_cycles > SECONDS_TO_CYCLES(10)) {
                should_evict = 1;
                printf("[Sweeper Core] Aging Eviction ➔ Established session went silent past idle timeout thresholds.\n");
            }
            if (should_evict) {
                rte_hash_del_key(fast_path_hash_table, key);
                rte_mempool_put(flow_entry_mempool, entry);
            }
        }
        rte_delay_ms(500);
    }
    return 0;
}

int main(int argc, char *argv[]) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    int ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_exit(EXIT_FAILURE, "EAL initialization failed\n");

    if (rte_lcore_count() < 3) {
        rte_exit(EXIT_FAILURE, "Error: This setup requires at least 3 logical cores (-l 1,2,3)\n");
    }

    pkt_mbuf_pool = rte_pktmbuf_pool_create("PKT_POOL", 128, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    flow_entry_mempool = rte_mempool_create("ENTRY_POOL", 256, sizeof(struct flow_entry), 
                                            0, 0, NULL, NULL, NULL, NULL, rte_socket_id(), 0);

    struct rte_hash_parameters hash_params = {
        .name = "STATEFUL_FLOW_TABLE",
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

    unsigned int main_core = rte_get_main_lcore();
    unsigned int data_core = rte_get_next_lcore(main_core, 0, 0);
    unsigned int sweep_core = rte_get_next_lcore(data_core, 0, 0);

    rte_eal_remote_launch(run_dataplane_worker, NULL, data_core);
    rte_eal_remote_launch(run_garbage_collector, NULL, sweep_core);
    printf("[Main Core %u] Control Plane Active.\n", main_core);
    rte_eal_mp_wait_lcore();
    rte_hash_free(fast_path_hash_table);
    return 0;
}

