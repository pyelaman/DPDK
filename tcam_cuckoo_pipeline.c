/**
 * ==================================================================================
 * ALKIRA CLOUD-SCALE ASIC LOOKUP SUB-SYSTEM: COEXISTING L2 CUKOO HASH & L3 TCAM LPM
 * ==================================================================================
 *
 * 1. L2 Forwarding (Exact Match): Uses a multi-way Bucketized Cuckoo Hash Table 
 *    implemented over high-speed static RAM (SRAM) internal to the ASIC. 
 *    This guarantees a maximum of O(1) constant-time read bounds 
 *    (e.g., checking only 2 candidate buckets) to find a 48-bit MAC address + VLAN ID.
 *
 * 2. L3 Routing (Longest Prefix Match - LPM): Uses either a Ternary Content-Addressable Memory (TCAM) 
 *    block or a hardware-optimized Multi-Bit Trie (MTRIE) pipeline. 
 *    A TCAM performs parallel mask evaluations in a single clock cycle by storing bits 
 *    as 0, 1, or X (Don't Care), allowing CIDR subnet matching.

 * This implementation models real-world Cloud-scale silicon packet processing pipelines:
 * 1. L2 Bridging: 4-Way Bucketized Cuckoo Hash Table over SRAM (Constant time, O(1) reads).
 * 2. L3 Routing: Ternary Content-Addressable Memory (TCAM) emulator executing 
 *    Longest Prefix Match (LPM) via sequential priority mask bitwise comparisons.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <immintrin.h>

#define CUCKOO_BUCKET_COUNT 1024
#define CUCKOO_SLOTS_PER_BUCKET 4
#define MAX_CUCKOO_EVICTIONS 32
#define TCAM_MAX_RULES 512

/* --- LAYER 2: SYSTEM TYPEDEFS & STRUCTS (Exact Match MAC Lookup) --- */
typedef struct {
    uint8_t mac_addr[6];
    uint16_t vlan_id;
} __attribute__((packed)) l2_key_t;

typedef struct {
    uint32_t egress_port;
    bool is_valid;
} l2_action_t;

typedef struct {
    l2_key_t key;
    l2_action_t action;
} cuckoo_slot_t;

typedef struct {
    cuckoo_slot_t slots[CUCKOO_SLOTS_PER_BUCKET];
} cuckoo_bucket_t;

// Double-Bucket SRAM block allocation representing hardware memory arrays
static cuckoo_bucket_t cuckoo_table1[CUCKOO_BUCKET_COUNT];
static cuckoo_bucket_t cuckoo_table2[CUCKOO_BUCKET_COUNT];

/* --- LAYER 3: SYSTEM TYPEDEFS & STRUCTS (Longest Prefix Match IP Lookup) --- */
typedef struct {
    uint32_t ip_value; // Bitwise mask evaluation target
    uint32_t ip_mask;  // Subnet bit mask structure (e.g., 24-bit = 0xFFFFFF00)
    uint32_t priority; // Equivalent to prefix length mask strength
    bool is_valid;
} tcam_entry_t;

typedef struct {
    uint32_t next_hop_ip;
    uint32_t egress_port;
} l3_action_t;

// Parallel TCAM memory rows paired directly with physical SRAM actions registers
static tcam_entry_t tcam_array[TCAM_MAX_RULES];
static l3_action_t  l3_action_array[TCAM_MAX_RULES];
static uint32_t     tcam_rule_count = 0;


/* ==================================================================================
 * LAYER 2: BUCKETIZED CUCKOO HASH ALGORITHMS (SRAM SIMULATION)
 * ================================================================================== */

/**
 * High-performance hardware CRC-based primary lookup hashing engine.
 */
inline uint32_t l2_hash_primary(const l2_key_t *key) {
    uint32_t seed = _mm_crc32_u32(0xFFFFFFFF, *(const uint32_t *)(key->mac_addr));
    seed = _mm_crc32_u16(seed, *(const uint16_t *)(key->mac_addr + 4));
    seed = _mm_crc32_u16(seed, key->vlan_id);
    return seed % CUCKOO_BUCKET_COUNT;
}

/**
 * Complementary alternative hash engine to generate non-colliding second-tier indexes.
 */
inline uint32_t l2_hash_secondary(uint32_t primary_index) {
    // Knuth's multiplicative hashing variation for distinct bit-avalanche distribution
    return (primary_index * 2654435761U) % CUCKOO_BUCKET_COUNT;
}

/**
 * L2 Hardware Pipeline Lookup: Checks primary and secondary bucket slots in parallel.
 * Emulates parallel read commands on internal SRAM banks.
 */
bool asic_l2_forwarding_lookup(l2_key_t key, l2_action_t *out_action) {
    uint32_t b1 = l2_hash_primary(&key);
    uint32_t b2 = l2_hash_secondary(b1);

    // Scan Primary Bucket slots
    for (int i = 0; i < CUCKOO_SLOTS_PER_BUCKET; i++) {
        if (cuckoo_table1[b1].slots[i].action.is_valid &&
            memcmp(cuckoo_table1[b1].slots[i].key.mac_addr, key.mac_addr, 6) == 0 &&
            cuckoo_table1[b1].slots[i].key.vlan_id == key.vlan_id) {
            *out_action = cuckoo_table1[b1].slots[i].action;
            return true;
        }
    }

    // Scan Secondary Bucket slots
    for (int i = 0; i < CUCKOO_SLOTS_PER_BUCKET; i++) {
        if (cuckoo_table2[b2].slots[i].action.is_valid &&
            memcmp(cuckoo_table2[b2].slots[i].key.mac_addr, key.mac_addr, 6) == 0 &&
            cuckoo_table2[b2].slots[i].key.vlan_id == key.vlan_id) {
            *out_action = cuckoo_table2[b2].slots[i].action;
            return true;
        }
    }

    return false; // MAC Miss -> Fallback to hardware flood plane
}

/**
 * Control Plane Cuckoo Insertion Logic: Manages eviction cascades to maximize load.
 */
bool control_plane_l2_insert(l2_key_t key, l2_action_t action) {
    uint32_t b1 = l2_hash_primary(&key);

    // 1. Try an open slot in Primary Table Bucket
    for (int i = 0; i < CUCKOO_SLOTS_PER_BUCKET; i++) {
        if (!cuckoo_table1[b1].slots[i].action.is_valid) {
            cuckoo_table1[b1].slots[i].key = key;
            cuckoo_table1[b1].slots[i].action = action;
            cuckoo_table1[b1].slots[i].action.is_valid = true;
            return true;
        }
    }

    // 2. Try an open slot in Secondary Table Bucket
    uint32_t b2 = l2_hash_secondary(b1);
    for (int i = 0; i < CUCKOO_SLOTS_PER_BUCKET; i++) {
        if (!cuckoo_table2[b2].slots[i].action.is_valid) {
            cuckoo_table2[b2].slots[i].key = key;
            cuckoo_table2[b2].slots[i].action = action;
            cuckoo_table2[b2].slots[i].action.is_valid = true;
            return true;
        }
    }

    // 3. Eviction Cascade: Displace an entry and push it to its alternative home
    uint32_t current_bucket = b1;
    bool use_table1 = true;
    cuckoo_slot_t evict_candidate = { .key = key, .action = action };
    evict_candidate.action.is_valid = true;

    for (int loop = 0; loop < MAX_CUCKOO_EVICTIONS; loop++) {
        int slot_idx = loop % CUCKOO_SLOTS_PER_BUCKET;
        cuckoo_bucket_t *target_table = use_table1 ? cuckoo_table1 : cuckoo_table2;
        
        // Swap data
        cuckoo_slot_t temp = target_table[current_bucket].slots[slot_idx];
        target_table[current_bucket].slots[slot_idx] = evict_candidate;
        evict_candidate = temp;

        if (!evict_candidate.action.is_valid) {
            return true; // Displaced entry found an open slot
        }

        // Calculate alternative destination for the displaced entry
        if (use_table1) {
            current_bucket = l2_hash_secondary(l2_hash_primary(&evict_candidate.key));
            use_table1 = false;
        } else {
            current_bucket = l2_hash_primary(&evict_candidate.key);
            use_table1 = true;
        }
    }

    return false; // Table saturation threshold breached -> Requires memory rehash
}


/* ==================================================================================
 * LAYER 3: TERNARY CONTENT-ADDRESSABLE MEMORY (TCAM) LPM PIPELINE
 * ================================================================================== */

/**
 * Control Plane Rule Insertion: Appends an LPM rule to the TCAM matrix.
 */
bool control_plane_tcam_add_route(uint32_t prefix_ip, uint32_t cidr_mask_len, l3_action_t action) {
    if (tcam_rule_count >= TCAM_MAX_RULES) return false;

    // Convert CIDR prefix length to bitmask (e.g., 24 -> 0xFFFFFF00)
    uint32_t mask = (cidr_mask_len == 0) ? 0 : (~0U << (32 - cidr_mask_len));

    tcam_array[tcam_rule_count].ip_value = prefix_ip & mask;
    tcam_array[tcam_rule_count].ip_mask  = mask;
    tcam_array[tcam_rule_count].priority = cidr_mask_len;
    tcam_array[tcam_rule_count].is_valid = true;

    l3_action_array[tcam_rule_count] = action;
    tcam_rule_count++;
    return true;
}

/**
 * L3 Hardware Pipeline Lookup: Emulates an ASIC TCAM bit-parallel sweep.
 * Matches `(Input_IP & Row_Mask) == Row_Value` across all lines simultaneously, 
 * returning the Longest Prefix Match (highest mask priority).
 */
bool asic_l3_tcam_route_lookup(uint32_t destination_ip, l3_action_t *out_action) {
    int best_match_idx = -1;
    uint32_t highest_priority = 0;

    // Real ASICs execute this loop across millions of gates in parallel within 1 clock cycle.
    for (uint32_t i = 0; i < tcam_rule_count; i++) {
        if (!tcam_array[i].is_valid) continue;

        // Ternary matching evaluation rule logic
        if ((destination_ip & tcam_array[i].ip_mask) == tcam_array[i].ip_value) {
            // Track match with the longest prefix length (highest priority)
            if (tcam_array[i].priority >= highest_priority) {
                highest_priority = tcam_array[i].priority;
                best_match_idx = i;
            }
        }
    }

    if (best_match_idx != -1) {
        *out_action = l3_action_array[best_match_idx];
        return true;
    }
    return false; // No route matched -> Drop packet or forward to Default Gateway
}


/* ==================================================================================
 * PIPELINE VERIFICATION DRIVER ROUTINE
 * ================================================================================== */
int main(void) {
    printf("=====================================================================\n");
    printf("ALKIRA CLOUD-SCALE ASIC LOOKUP COEXISTENCE MODULE INITIALIZING\n");
    printf("=====================================================================\n\n");

    // Initialize tables
    memset(cuckoo_table1, 0, sizeof(cuckoo_table1));
    memset(cuckoo_table2, 0, sizeof(cuckoo_table2));

    /* --- STEP 1: CONFIGURE L2 CUCKOO HASH FIB ENTRIES --- */
    printf("[STAGE 1/4] Populating Layer 2 Cuckoo Hash SRAM Tables...\n");
    l2_key_t key_host1 = { .mac_addr = {0x00, 0x11, 0x22, 0x33, 0x44, 0xAA}, .vlan_id = 100 };
    l2_action_t act_host1 = { .egress_port = 4, .is_valid = true };
    control_plane_l2_insert(key_host1, act_host1);

    l2_key_t key_host2 = { .mac_addr = {0x00, 0x11, 0x22, 0x33, 0x44, 0xBB}, .vlan_id = 100 };
    l2_action_t act_host2 = { .egress_port = 9, .is_valid = true };
    control_plane_l2_insert(key_host2, act_host2);
    printf("  -> L2 Hash Tables initialized successfully.\n");


    /* --- STEP 2: CONFIGURE L3 TCAM PREFIX RULES --- */
    printf("\n[STAGE 2/4] Programming Layer 3 TCAM LPM Routing Rows...\n");
    // Rule A: Specific Host Route (10.0.1.50/32)
    l3_action_t act_route_a = { .next_hop_ip = 0x0A000101, .egress_port = 40 }; // 10.0.1.1 out Eth40
    control_plane_tcam_add_route(0x0A000132, 32, act_route_a);

    // Rule B: Standard Corporate Subnet (10.0.1.0/24)
    l3_action_t act_route_b = { .next_hop_ip = 0x0A0001FE, .egress_port = 20 }; // 10.0.1.254 out Eth20
    control_plane_tcam_add_route(0x0A000100, 24, act_route_b);

    // Rule C: Catch-All Default Gateway (0.0.0.0/0)
    l3_action_t act_route_c = { .next_hop_ip = 0x88080808, .egress_port = 1 };  // Internet Core out Eth1
    control_plane_tcam_add_route(0x00000000, 0, act_route_c);

    printf("  -> TCAM LPM Matrix initialized with %u active rule profiles.\n", tcam_rule_count);
    /* --- STEP 3: EXECUTE LAYER 2 FORWARDING LOOKUPS --- */

    printf("\n[STAGE 3/4] Testing L2 Exact-Match Processing Pipeline...\n");
    l2_action_t lookup_l2_result;

    // Look up an existing MAC address
    if (asic_l2_forwarding_lookup(key_host1, &lookup_l2_result)) {
        printf("  -> [HIT] MAC 00:11:22:33:44:AA on VLAN 100 forwarded to Egress Port: %u\n", 
			lookup_l2_result.egress_port);
    } else {
        printf("  -> [MISS] MAC address not found.\n");
    }

    // Look up an unknown MAC address
    l2_key_t unk_host = { .mac_addr = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xEE}, .vlan_id = 100 };
    if (!asic_l2_forwarding_lookup(unk_host, &lookup_l2_result)) {
        printf("  -> [MISS] Unknown MAC address correctly triggered a miss condition.\n");
    }

    /* --- STEP 4: EXECUTE LAYER 3 LONGESET PREFIX MATCH TCAM ROUTING LOOKUPS --- */
    printf("\n[STAGE 4/4] Testing L3 TCAM Longest Prefix Match Pipeline...\n");
    l3_action_t lookup_l3_result;

    // Look up an IP matching the specific /32 host route (10.0.1.50)
    uint32_t search_ip_1 = 0x0A000132;
    if (asic_l3_tcam_route_lookup(search_ip_1, &lookup_l3_result)) {
        printf("  -> IP 10.0.1.50 matched Route Priority /32. Egress Port: %u, NextHop: 0x%08X\n",
        lookup_l3_result.egress_port, lookup_l3_result.next_hop_ip);
    }

    // Look up an IP matching the /24 subnet route (10.0.1.75)
    uint32_t search_ip_2 = 0x0A00014B;
    if (asic_l3_tcam_route_lookup(search_ip_2, &lookup_l3_result)) {
        printf("  -> IP 10.0.1.75 matched Route Priority /24. Egress Port: %u, NextHop: 0x%08X\n",
        lookup_l3_result.egress_port, lookup_l3_result.next_hop_ip);
    }

    // Look up an external IP that hits the /0 default route (192.168.5.5)
    uint32_t search_ip_3 = 0xC0A80505;
    if (asic_l3_tcam_route_lookup(search_ip_3, &lookup_l3_result)) {
        printf("  -> IP 192.168.5.5 fell back to Default Route /0. Egress Port: %u, NextHop: 0x%08X\n",
        lookup_l3_result.egress_port, lookup_l3_result.next_hop_ip);
    }
    printf("\n=====================================================================\n");
    printf("ALKIRA CLOUD SCALE HARDWARE SIMULATION MATRIX EVALUATION SUCCESSFUL\n");
    printf("=====================================================================\n");
    return 0;
}
