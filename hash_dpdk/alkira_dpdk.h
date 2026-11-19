#ifndef ALKIRA_DPDK_H
#define ALKIRA_DPDK_H

#include <stdint.h>
#include <stdbool.h>
#include <rte_common.h>
#include <rte_memory.h>
#include <rte_eal.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>   // Must precede ethdev
#include <rte_ethdev.h> // Provides rte_eth_tx_burst
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#ifndef RTE_TCP_OPT_END
#define RTE_TCP_OPT_END 0  // End of Option List
#endif

#ifndef RTE_TCP_OPT_NOP
#define RTE_TCP_OPT_NOP 1  // No Operation (Padding)
#endif

#ifndef RTE_TCP_OPT_MSS
#define RTE_TCP_OPT_MSS 2  // Maximum Segment Size
#endif

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

