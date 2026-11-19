#include "alkira_dpdk.h"

/* Canonical 5-Tuple sorting to pin downstream/upstream paths to identical cores */
void extract_canonical_key(const struct rte_ipv4_hdr *inner_ip, 
                           const struct rte_tcp_hdr *inner_tcp, 
                           flow_key_t *c_key) {
    if (inner_ip->src_addr < inner_ip->dst_addr) {
        c_key->src_ip   = inner_ip->src_addr;
        c_key->dst_ip   = inner_ip->dst_addr;
        c_key->src_port = inner_tcp->src_port;
        c_key->dst_port = inner_tcp->dst_port;
    } else {
        c_key->src_ip   = inner_ip->dst_addr;
        c_key->dst_ip   = inner_ip->src_addr;
        c_key->src_port = inner_tcp->dst_port;
        c_key->dst_port = inner_tcp->src_port;
    }
    c_key->protocol = inner_ip->next_proto_id;
}
