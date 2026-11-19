#include "alkira_core.h"

static firewall_node_t firewall_pool[ALKIRA_MAX_FIREWALLS];
static uint8_t active_firewalls_count = 0;

void initialize_firewall_pool(void) {
    // Populate auto-scaled virtual firewall targets inside the CXP segment
    firewall_pool[0] = (firewall_node_t){.fw_ip = 0x0A0A010A, .fw_id = 101, .is_alive = true}; // 10.10.1.10
    firewall_pool[1] = (firewall_node_t){.fw_ip = 0x0A0A010B, .fw_id = 102, .is_alive = true}; // 10.10.1.11
    active_firewalls_count = 2;
}

/* Computes a fast asymmetric-safe 5-tuple hash to pin flows to firewalls */
uint8_t select_firewall_instance(const flow_key_t *raw_flow) {
    uint32_t hash_accumulator = 0;
    
    // Symmetric XOR blending to ensure return legs hit identical bucket indexes
    hash_accumulator ^= (raw_flow->src_ip ^ raw_flow->dst_ip);
    hash_accumulator ^= (raw_flow->src_port ^ raw_flow->dst_port);
    hash_accumulator ^= raw_flow->protocol;

    uint8_t attempt = 0;
    while (attempt < ALKIRA_MAX_FIREWALLS) {
        uint8_t target_idx = (hash_accumulator + attempt) % active_firewalls_count;
        if (firewall_pool[target_idx].is_alive) {
            return target_idx; // Pinned active firewall index found
        }
        attempt++; // Linear probing fallback if a firewall drops offline
    }
    return 0xFF; // Error: No healthy firewall targets present
}

