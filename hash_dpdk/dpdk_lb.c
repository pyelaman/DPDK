#include "alkira_dpdk.h"
#include <rte_hash_crc.h>

typedef struct {
    uint32_t fw_ip;
    uint16_t port_id;
    bool     is_alive;
} dpdk_fw_node_t;

static dpdk_fw_node_t active_pool[ALKIRA_MAX_FIREWALLS];
static uint8_t active_fw_count = 0;

/* Leverages hardware acceleration algorithms via CRC32 instruction strings */
uint16_t select_dpdk_firewall_node(const flow_key_t *c_key) {
    if (unlikely(active_fw_count == 0)) return 0xFFFF;

    // Fast symmetric hardware hash distribution path
    uint32_t hash_token = rte_hash_crc(c_key, sizeof(flow_key_t), 0);
    
    for (uint8_t i = 0; i < ALKIRA_MAX_FIREWALLS; i++) {
        uint8_t idx = (hash_token + i) % active_fw_count;
        if (active_pool[idx].is_alive) {
            return active_pool[idx].port_id;
        }
    }
    return 0xFFFF; // Drop packet path if no active firewall destinations exist
}

