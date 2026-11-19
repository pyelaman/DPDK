#include <string.h>
#include "alkira_core.h"

/* Simplified State Table mapping a normalized flow key to a designated Egress CXP path/Node ID */
typedef struct {
    flow_key_t canonical_key;
    uint16_t   assigned_cxp_node;
    bool       is_active;
} state_entry_t;

#define STATE_TABLE_SIZE 1024
static state_entry_t global_state_table[STATE_TABLE_SIZE];

/* Hashes the normalized canonical key */
static uint32_t hash_flow_key(const flow_key_t *key) {
    uint32_t hash = 0;
    const uint8_t *ptr = (const uint8_t *)key;
    for (size_t i = 0; i < sizeof(flow_key_t); i++) {
        hash = (hash * 31) + ptr[i];
    }
    return hash % STATE_TABLE_SIZE;
}

/* Enforces absolute path symmetry by sorting IP and Port fields order-independently */
void create_canonical_key(const flow_key_t *raw_flow, flow_key_t *canonical_flow) {
    if (raw_flow->src_ip < raw_flow->dst_ip) {
        canonical_flow->src_ip   = raw_flow->src_ip;
        canonical_flow->dst_ip   = raw_flow->dst_ip;
        canonical_flow->src_port = raw_flow->src_port;
        canonical_flow->dst_port = raw_flow->dst_port;
    } else {
        // Swap values to enforce canonical order across asymmetric trajectories
        canonical_flow->src_ip   = raw_flow->dst_ip;
        canonical_flow->dst_ip   = raw_flow->src_ip;
        canonical_flow->src_port = raw_flow->dst_port;
        canonical_flow->dst_port = raw_flow->src_port;
    }
    canonical_flow->protocol = raw_flow->protocol;
}

/* Pins or retrieves the execution path to enforce symmetric packet distribution */
uint16_t enforce_traffic_symmetry(const flow_key_t *raw_flow, uint16_t local_cxp_id) {
    flow_key_t c_key;
    memset(&c_key, 0, sizeof(flow_key_t));
    create_canonical_key(raw_flow, &c_key);

    uint32_t slot = hash_flow_key(&c_key);
    
    // Look up or establish state affinity block
    if (global_state_table[slot].is_active && 
        memcmp(&global_state_table[slot].canonical_key, &c_key, sizeof(flow_key_t)) == 0) {
        return global_state_table[slot].assigned_cxp_node; // Return pinned node path
    }

    // Cache first-hop packet direction path dynamically
    global_state_table[slot].canonical_key = c_key;
    global_state_table[slot].assigned_cxp_node = local_cxp_id;
    global_state_table[slot].is_active = true;
    
    return local_cxp_id;
}

