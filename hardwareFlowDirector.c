#include <stdio.h>
#include <stdint.h>
#include <rte_ethdev.h>
#include <rte_flow.h>
#include <rte_common.h>
#include <rte_branch_prediction.h>

#define VXLAN_UDP_PORT 4789

/*
 * TCAM Matching Efficiency: This setup offloads multi-layered parsing loops entirely to the network card, 
 * shielding CPU caches from overhead.
 *
 * Zero-Cycle Context Discovery: The RTE_FLOW_ACTION_TYPE_MARK action lets worker threads identify the 
 * packet's tunnel context and network slice instantly via a direct hardware stamp, completely bypassing 
 * software layer processing
 *
*/

/**
 * Directs specific incoming tunneled VXLAN traffic straight to a designated 
 * hardware core queue using the NIC's physical Flow Director (FDIR) block.
 *
 * @param port_id The target physical network interface identifier.
 * @param target_queue_id The specific RX queue tied to a pinned lcore thread.
 * @param matching_vni The target Virtual Network Identifier (e.g., 20050).
 * @return Struct pointer to the active hardware rule instance, or NULL on error.
 */
struct rte_flow* generate_hardware_fdir_vxlan_rule(uint16_t port_id, 
                                                  uint16_t target_queue_id, 
                                                  uint32_t matching_vni) 
{
    // Allocate space for our pattern definitions and hardware action statements
    struct rte_flow_attr attr;
    struct rte_flow_item pattern[5]; // End, Eth, IPv4, UDP, VXLAN
    struct rte_flow_action actions[3]; // End, Queue, Mark
    struct rte_flow_error error;
    struct rte_flow *flow_handle = NULL;

    /* --- STEP 1: DEFINE RULE DIRECTIONAL ATTRIBUTES --- */
    memset(&attr, 0, sizeof(struct rte_flow_attr));
    attr.ingress = 1;  // Apply strictly to incoming packet paths
    attr.priority = 0; // Highest processing precedence tier

    /* --- STEP 2: BUILD FLOW PATTERN LAYER STRIPS --- */
    memset(pattern, 0, sizeof(pattern));

    // Layer 0: Generic Ether Layer (Pass all base traffic to next parser)
    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;

    // Layer 1: Outer IPv4 Header Mask
    struct rte_flow_item_ipv4 ip_spec;
    struct rte_flow_item_ipv4 ip_mask;
    memset(&ip_spec, 0, sizeof(struct rte_flow_item_ipv4));
    memset(&ip_mask, 0, sizeof(struct rte_flow_item_ipv4));
    pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
    pattern[1].spec = &ip_spec;
    pattern[1].mask = &ip_mask;

    // Layer 2: UDP Header (Strictly target the default standard VXLAN destination port)
    struct rte_flow_item_udp udp_spec;
    struct rte_flow_item_udp udp_mask;
    memset(&udp_spec, 0, sizeof(struct rte_flow_item_udp));
    memset(&udp_mask, 0, sizeof(struct rte_flow_item_udp));
    
    udp_spec.hdr.dst_port = rte_cpu_to_be_16(VXLAN_UDP_PORT);
    udp_mask.hdr.dst_port = RTE_BE16(0xFFFF); // Exact match assertion
    
    pattern[2].type = RTE_FLOW_ITEM_TYPE_UDP;
    pattern[2].spec = &udp_spec;
    pattern[2].mask = &udp_mask;

    // Layer 3: VXLAN Header Core Parameter Filtering (Match explicit tenant transit identification maps)
    struct rte_flow_item_vxlan vxlan_spec;
    struct rte_flow_item_vxlan vxlan_mask;
    memset(&vxlan_spec, 0, sizeof(struct rte_flow_item_vxlan));
    memset(&vxlan_mask, 0, sizeof(struct rte_flow_item_vxlan));

    /* 
     * VXLAN VNIs are 24-bit identities. In DPDK structures, the VNI is stored across 
     * a 3-byte array inside the header frame boundaries.
     */
    vxlan_spec.hdr.vni[0] = (uint8_t)((matching_vni >> 16) & 0xFF);
    vxlan_spec.hdr.vni[1] = (uint8_t)((matching_vni >> 8) & 0xFF);
    vxlan_spec.hdr.vni[2] = (uint8_t)(matching_vni & 0xFF);

    vxlan_mask.hdr.vni[0] = 0xFF;
    vxlan_mask.hdr.vni[1] = 0xFF;
    vxlan_mask.hdr.vni[2] = 0xFF;

    pattern[3].type = RTE_FLOW_ITEM_TYPE_VXLAN;
    pattern[3].spec = &vxlan_spec;
    pattern[3].mask = &vxlan_mask;

    // Layer 4: Close the matching block pipeline array
    pattern[4].type = RTE_FLOW_ITEM_TYPE_END;

    /* --- STEP 3: CONSTRUCT TARGET ACTIONS HARDWARE ACTIONS --- */
    memset(actions, 0, sizeof(actions));

    // Action 1: Assign a specific Hardware Flow Mark ID to the packet
    // This allows the fast-path lcore loop to identify the flow context instantly using 'm->hash.fdir.hi'
    struct rte_flow_action_mark mark_action;
    mark_action.id = 0xAA55; // Custom unique metadata indicator tag
    actions[0].type = RTE_FLOW_ACTION_TYPE_MARK;
    actions[0].conf = &mark_action;

    // Action 2: Steer traffic directly to the designated core queue
    struct rte_flow_action_queue queue_action;
    queue_action.index = target_queue_id;
    actions[1].type = RTE_FLOW_ACTION_TYPE_QUEUE;
    actions[1].conf = &queue_action;

    // Action 3: Finalize structural action block layout array
    actions[2].type = RTE_FLOW_ACTION_TYPE_END;

    /* --- STEP 4: VERIFY COMPLIANCE AND COMMUTE BOUNDARY RULES --- */
    int validation_check = rte_flow_validate(port_id, &attr, pattern, actions, &error);
    if (unlikely(validation_check != 0)) {
        printf("[ERROR] Physical NIC rejected the FDIR configuration blueprint. Reason: %s\n", 
               error.message ? error.message : "Unidentified constraint failure");
        return NULL;
    }

    // Safely write the rule into the network card's internal TCAM memory tables
    flow_handle = rte_flow_create(port_id, &attr, pattern, actions, &error);
    if (unlikely(flow_handle == NULL)) {
        printf("[ERROR] Failed to commit the FDIR configuration to hardware interface. Reason: %s\n", 
               error.message ? error.message : "Hardware table allocation exhaustion");
        return NULL;
    }

    printf("[SUCCESS] FDIR Offload rule deployed on Port %u. Steering VNI %u packets to Queue %u.\n", 
           port_id, matching_vni, target_queue_id);
    
    return flow_handle;
}

/*
 * When the NIC encounters an matching incoming packet, it handles classification entirely in hardware. 
 * It directs the packet straight into the assigned target_queue_id and stamps the metadata tag directly 
 * into the packet descriptor (mbuf).
 * The fast-path worker loop then bypasses expensive software-defined protocol parsing and reads 
 * the classification directly from the descriptor
 */

void process_fdir_packets_optimized(uint16_t port_id, uint16_t assigned_queue) {
    struct rte_mbuf *mbufs[32];
    // Retrieve packet burst directly from the pre-classified hardware queue
    uint16_t nb_rx = rte_eth_rx_burst(port_id, assigned_queue, mbufs, 32);

    for (uint16_t i = 0; i < nb_rx; i++) {
        struct rte_mbuf *m = mbufs[i];

        // Check if the NIC's Flow Director (FDIR) flags are active on this packet
        if (m->ol_flags & RTE_MBUF_F_RX_FDIR_ID) {
            // Read the pre-stamped hardware mark ID directly
            uint32_t flow_mark = m->hash.fdir.hi;
            
            if (likely(flow_mark == 0xAA55)) {
                /* 
                 * BYPASS SUCCESSFUL:
                 * We know this packet belongs to VNI 20050 without parsing 
                 * any outer L2, L3, UDP, or VXLAN header bytes in software.
                 */
                uint8_t *inner_payload = rte_pktmbuf_mtod(m, uint8_t *) + 14 + 20 + 8 + 8;
                // Directly execute stateful multi-cloud microsegmentation actions...
            }
        }
        rte_pktmbuf_free(m);
    }
}

int main() {
   return 0;
}

