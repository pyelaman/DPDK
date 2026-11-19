#include <stdio.h>
#include <stdint.h>
#include <rte_common.h>
#include <rte_mbuf.h>
#include <rte_hash.h>
#include <rte_acl.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_ether.h>
#include <rte_branch_prediction.h>

#include "dataplane_structs.h"

#define BURST_SIZE 32

/* Global References to initialized DPDK tables (setup by Control Plane) */
extern struct rte_hash *fast_path_hash_table;
extern struct rte_acl_ctx *slow_path_acl_ctx;
extern struct rte_mempool *flow_entry_mempool;

/* Helper function to extract 5-tuple from raw packet buffer memory */
static inline int
extract_5tuple(struct rte_mbuf *m, struct flow_key *key) {
    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    
    /* Ensure packet is IPv4 */
    if (eth_hdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
        return -1;
    }

    struct rte_ipv4_hdr *ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
    key->src_ip = ipv4_hdr->src_addr;
    key->dst_ip = ipv4_hdr->dst_addr;
    key->proto  = ipv4_hdr->next_proto_id;

    if (key->proto == IPPROTO_TCP) {
        struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(ipv4_hdr + 1);
        key->src_port = tcp->src_port;
        key->dst_port = tcp->dst_port;
    } else if (key->proto == IPPROTO_UDP) {
        struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(ipv4_hdr + 1);
        key->src_port = udp->src_port;
        key->dst_port = udp->dst_port;
    } else {
        key->src_port = 0;
        key->dst_port = 0;
    }
    return 0;
}

/* Run-to-completion Vector Burst Pipeline Loop */
void 
dataplane_worker_loop(uint16_t port_in, uint16_t port_out, uint16_t queue_id) {
    struct rte_mbuf *pkts[BURST_SIZE];
    printf("Data Plane Worker core %u actively polling interface.\n", rte_lcore_id());

    for (;;) {
        /* 1. Fetch vector burst from the assigned interface hardware queue */
        const uint16_t nb_rx = rte_eth_rx_burst(port_in, queue_id, pkts, BURST_SIZE);
        if (unlikely(nb_rx == 0)) {
            continue;
        }

        /* Arrays to hold extracted keys and resolved positions */
        struct flow_key keys[BURST_SIZE];
        const void *key_ptrs[BURST_SIZE];
        int32_t positions[BURST_SIZE];
        void *flow_data[BURST_SIZE];
        uint32_t acl_results[BURST_SIZE];
        
        uint16_t valid_pkts_count = 0;
        uint16_t valid_pkt_indices[BURST_SIZE];

        /* Step 2: Prefetch and parse headers */
        for (uint16_t i = 0; i < nb_rx; i++) {
            /* Prefetch the mbuf data payload segment 2 steps ahead to avoid cache stalling */
            if (i + 2 < nb_rx) {
                rte_prefetch0(rte_pktmbuf_mtod(pkts[i + 2], void *));
            }

            if (likely(extract_5tuple(pkts[i], &keys[valid_pkts_count]) == 0)) {
                key_ptrs[valid_pkts_count] = &keys[valid_pkts_count];
                valid_pkt_indices[valid_pkts_count] = i;
                valid_pkts_count++;
            } else {
                /* Non-IP / Unknown Layer 4 packet types dropped immediately */
                rte_pktmbuf_free(pkts[i]);
            }
        }

        if (unlikely(valid_pkts_count == 0)) continue;

        /* Step 3: Fast-Path Bulk Cuckoo Hash Evaluation (O(1) Matrix Lookup) */
        rte_hash_lookup_bulk_data(fast_path_hash_table, key_ptrs, valid_pkts_count, positions, flow_data);

        /* Step 4: Process Lookup Results */
        for (uint16_t i = 0; i < valid_pkts_count; i++) {
            uint16_t orig_idx = valid_pkt_indices[i];
            struct rte_mbuf *m = pkts[orig_idx];
            struct flow_entry *entry = (struct flow_entry *)flow_data[i];

            /* Case A: Cache Hit (Fast-Path Entry Present) */
            if (likely(positions[i] >= 0 && entry != NULL)) {
                entry->total_packets++;
                entry->total_bytes += m->pkt_len;

                if (entry->verdict == VERDICT_FORWARD) {
                    /* Perform dynamic header transformation (NAT rewrite) */
                    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
                    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
                    
                    ip->src_addr = entry->nat_src_ip; // Overwrite source with NAT Translation IP
                    
                    /* Emit transformed packet out of target physical TX ring */
                    rte_eth_tx_burst(port_out, queue_id, &m, 1);
                } else {
                    rte_pktmbuf_free(m); // Explicit Drop Action
                }
            } 
            /* Case B: Cache Miss (Fall back to Slow-Path ACL Trie Tree Grid) */
            else {
                /* Prepare packet context pointer for standard ACL resolution */
                const uint8_t *acl_data_ptr = rte_pktmbuf_mtod(m, const uint8_t *) + sizeof(struct rte_ether_hdr);
                
                rte_acl_classify(slow_path_acl_ctx, &acl_data_ptr, &acl_results[i], 1, 1);

                /* Allocate a entry from memory matrix to cache this evaluation */
                struct flow_entry *new_entry;
                if (unlikely(rte_mempool_get(flow_entry_mempool, (void **)&new_entry) < 0)) {
                    /* Mempool depleted, safety fallback: drop packet to defend processing boundaries */
                    rte_pktmbuf_free(m);
                    continue;
                }

                /* Populate new tracking entry parameters */
                new_entry->key = keys[i];
                new_entry->total_packets = 1;
                new_entry->total_bytes = m->pkt_len;
                new_entry->verdict = (acl_results[i] == VERDICT_FORWARD) ? VERDICT_FORWARD : VERDICT_DROP;
                
                /* Simple NAT dynamic allocation assignment simulation */
                new_entry->nat_src_ip = rte_cpu_to_be_32(0x0A0000FE); // 10.0.0.254 Pool IP
                new_entry->nat_src_port = rte_cpu_to_be_16(50001);

                /* Write entry references back into fast-path Cuckoo tables locklessly */
                int32_t ret = rte_hash_add_key_data(fast_path_hash_table, &keys[i], new_entry);
                if (unlikely(ret < 0)) {
                    /* Hash insertion failure (e.g. Cuckoo eviction table limit reached) */
                    rte_mempool_put(flow_entry_mempool, new_entry);
                }

                /* Complete routing action based on computed rule verdict */
                if (new_entry->verdict == VERDICT_FORWARD) {
                    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
                    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
                    ip->src_addr = new_entry->nat_src_ip;
                    rte_eth_tx_burst(port_out, queue_id, &m, 1);
                } else {
                    rte_pktmbuf_free(m);
                }
            }
        }
    }
}

