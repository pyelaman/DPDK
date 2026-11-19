#ifndef ALKIRA_DPDK_H
#define ALKIRA_DPDK_H

#include <stdint.h>
#include <stdbool.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#define VXLAN_PORT 4789
#define ALKIRA_MSS_FLOOR 1360
#define ALKIRA_MAX_FIREWALLS 8

/* Canonical DPDK Unified Flow Key Layout */
typedef struct {
    rte_be32_t src_ip;
    rte_be32_t dst_ip;
    rte_be16_t src_port;
    rte_be16_t dst_port;
    uint8_t    protocol;
} __attribute__((packed)) flow_key_t;

/* Combined outer encap dimensions helper */
#define OUTER_VXLAN_ENCAP_LEN (\
    sizeof(struct rte_ether_hdr) + \
    sizeof(struct rte_ipv4_hdr)  + \
    sizeof(struct rte_udp_hdr)   + \
    8 /* Fixed 8-byte VXLAN Header */)

#endif

