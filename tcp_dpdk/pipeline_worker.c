#include "alkira_dpdk.h"

extern void extract_canonical_key(const struct rte_ipv4_hdr *inner_ip, const struct rte_tcp_hdr *inner_tcp, flow_key_t *c_key);
extern uint16_t select_dpdk_firewall_node(const flow_key_t *c_key);
extern bool process_dpdk_mss_clamp(struct rte_mbuf *m);

/* High-Performance Burst Processing Ring Loop Hook */
void process_alkira_transit_burst(uint16_t port_id, uint16_t queue_id, struct rte_mbuf **pkts, uint16_t nb_pkts) {
    uint16_t sent_pkts;
    
    for (uint16_t i = 0; i < nb_pkts; i++) {
        struct rte_mbuf *m = pkts[i];

        // Access inner layer tracking variables using target offsets
        uint32_t inner_ip_offset = OUTER_VXLAN_ENCAP_LEN + sizeof(struct rte_ether_hdr);
        struct rte_ipv4_hdr *inner_ip = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *,
                                                                inner_ip_offset);
        
        uint32_t inner_ip_len = (inner_ip->version_ihl & RTE_IPV4_HDR_IHL_MASK) * RTE_IPV4_IHL_MULTIPLIER;
        struct rte_tcp_hdr *inner_tcp = rte_pktmbuf_mtod_offset(m, struct rte_tcp_hdr *, 
                                                        inner_ip_offset + inner_ip_len);

        flow_key_t canonical_key;
        extract_canonical_key(inner_ip, inner_tcp, &canonical_key);

        // 1. Identify Target Firewall Affinity Path
        uint16_t target_fw_port = select_dpdk_firewall_node(&canonical_key);

        // 2. Adjust MSS Boundaries Inline
        process_dpdk_mss_clamp(m);

        // 3. Forward Modified Frame directly out to the respective interface TX ring
        if (likely(target_fw_port != 0xFFFF)) {
            sent_pkts = rte_eth_tx_burst(target_fw_port, queue_id, &m, 1);
            if (unlikely(sent_pkts < 1)) {
                rte_pktmbuf_free(m); // Drop if egress queue ring is congested
            }
        } else {
            rte_pktmbuf_free(m); // Security Exception drop action
        }
    }
}

