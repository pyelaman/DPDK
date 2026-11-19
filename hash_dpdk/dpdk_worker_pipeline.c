#include "alkira_state.h"

extern void extract_canonical_key(const struct rte_ipv4_hdr *inner_ip, const struct rte_tcp_hdr *inner_tcp, flow_key_t *c_key);
extern uint16_t select_dpdk_firewall_node(const flow_key_t *c_key);
extern bool process_dpdk_mss_clamp(struct rte_mbuf *m);
extern void update_tcp_state_machine(session_meta_t *meta, const struct rte_tcp_hdr *tcp, uint64_t hertz_freq);
extern session_meta_t *get_or_create_session(const flow_key_t *c_key, uint16_t default_fw_port, bool *is_new_flow);

#define BURST_SIZE 32

/* Processes massive continuous packet arrays leveraging vectorized parallel caching lookups */
void process_alkira_pipeline_with_state(uint16_t port_id, uint16_t queue_id, struct rte_mbuf **pkts, uint16_t nb_pkts) {
    flow_key_t keys[BURST_SIZE];
    const void *key_ptrs[BURST_SIZE];
    int32_t positions[BURST_SIZE];
    struct rte_ipv4_hdr *inner_ips[BURST_SIZE];
    struct rte_tcp_hdr *inner_tcps[BURST_SIZE];
    bool valid_mask[BURST_SIZE] = {false};
    uint16_t tx_targets[BURST_SIZE];

    // --- PHASE 1: PRE-FETCH & DISTRIBUTE PARSING LAYER ---
    for (uint16_t i = 0; i < nb_pkts; i++) {
        struct rte_mbuf *m = pkts[i];
        
        // Issue early hardware pipelining prefetch hints to reduce CPU execution stalls
        rte_prefetch0(rte_pktmbuf_mtod(m, void *));

        uint32_t inner_ip_offset = OUTER_VXLAN_ENCAP_LEN + sizeof(struct rte_ether_hdr);
        if (unlikely(m->pkt_len < inner_ip_offset + sizeof(struct rte_ipv4_hdr))) {
            tx_targets[i] = 0xFFFF; // Mark for drop
            continue;
        }

        inner_ips[i] = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, inner_ip_offset);
        
        if (likely(inner_ips[i]->next_proto_id == IPPROTO_TCP)) {
            uint32_t ip_len = (inner_ips[i]->version_ihl & RTE_IPV4_HDR_IHL_MASK) * RTE_IPV4_IHL_MULTIPLIER;
            inner_tcps[i] = rte_pktmbuf_mtod_offset(m, struct rte_tcp_hdr *, inner_ip_offset + ip_len);
            
            // Build canonical tracking constraint key safely
            extract_canonical_key(inner_ips[i], inner_tcps[i], &keys[i]);
            key_ptrs[i] = &keys[i];
            valid_mask[i] = true;
            tx_targets[i] = 0xFFFF; // Default state init
        } else {
            // Bypass non-TCP data or pass directly down basic routing rules
            tx_targets[i] = 0xFFFF;
        }
    }

    // --- PHASE 2: BATCH BULK VECTOR RUNTIME LOOKUP ---
    extern alkira_state_engine_t state_engine;
    
    // Perform bulk lookup over the 32 packet context tokens simultaneously
    rte_hash_lookup_bulk(state_engine.hash_table_ctx, key_ptrs, nb_pkts, positions);

    // --- PHASE 3: COMPONENT ORCHESTRATION & STATE RESOLUTION ---
    uint64_t current_tsc = rte_get_tsc_cycles();
    uint64_t tsc_hz = rte_get_tsc_hz();

    for (uint16_t i = 0; i < nb_pkts; i++) {
        struct rte_mbuf *m = pkts[i];
        
        if (unlikely(!valid_mask[i])) {
            rte_pktmbuf_free(m);
            continue;
        }

        session_meta_t *session_state = NULL;
        int32_t pos = positions[i];

        if (likely(pos >= 0)) {
            // Cache record match hit
            session_state = &state_engine.metadata_array[pos];
            session_state->last_seen_tsc = current_tsc;
        } else {
            // Cache miss: dynamically spin up state node tracking block
            bool is_new;
            uint16_t dynamic_fw_target = select_dpdk_firewall_node(&keys[i]);
            session_state = get_or_create_session(&keys[i], dynamic_fw_target, &is_new);
        }

        if (unlikely(session_state == NULL)) {
            rte_pktmbuf_free(m);
            continue;
        }

        // Apply state tracking counters update
        session_state->packet_count++;
        session_state->byte_count += m->pkt_len;

        // Process TCP layer execution tracking
        update_tcp_state_machine(session_state, inner_tcps[i], tsc_hz);

        /* 
         * DIRECTIONAL PORT_ID EVALUATION LOGIC:
         * If the frame comes from an external cloud domain, we apply policy rules and send it 
         * into our sticky security appliance. If it comes back from that service instance, 
         * we clear transit boundaries and push it directly down to the target provider gateway port.
         */
        if (port_id != session_state->assigned_fw_port) {
            // Inbound Leg: Check if connection init setup needs MSS scale clamping modifications
            if (inner_tcps[i]->tcp_flags & RTE_TCP_SYN_FLAG) {
                process_dpdk_mss_clamp(m);
            }
            tx_targets[i] = session_state->assigned_fw_port;
        } else {
            // Return Leg: Packet returned from Firewall, forward to the cross-cloud exit trunk interface
            // For example, if it arrived on Port 0, send to Port 1 (AWS <-> Azure transit interface pairs)
            tx_targets[i] = (port_id == 0) ? 1 : 0; 
        }

        // --- PHASE 4: RE-RING TX BUFFER TRANSMISSION ---
        uint16_t dest_port = tx_targets[i];
        if (likely(dest_port != 0xFFFF)) {
            if (unlikely(rte_eth_tx_burst(dest_port, queue_id, &m, 1) < 1)) {
                rte_pktmbuf_free(m); // Drop packet if targeted TX ring overflows
            }
        } else {
            rte_pktmbuf_free(m); // Drop due to internal path failure
        }
    }
}

