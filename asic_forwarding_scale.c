#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

#define TCAM_MAX_ROWS 8
#define STRIDE_BITS 4              // 4-bit stride means 16 pointers per trie node level
#define STRIDE_SIZE (1 << STRIDE_BITS) 
#define PACKET_COUNT 3

// --- DATA STRUCTURES ---

// 1. TCAM Row Representation
typedef struct {
    uint32_t tenant_id;   // Virtual network profile isolation mapping
    uint32_t ip_data;     // Binary prefix comparison bits
    uint32_t ip_mask;     // Ternary ternary mask (1 = Match, 0 = "Don't Care" X)
    uint32_t prefix_len;  // Used by priority encoder to settle overlapping row matches
    char remote_vtep[32]; // Next-hop Virtual Tunnel End Point destination IP
} tcam_row_t;

// 2. Hardware-Optimized Multi-Bit Radix Trie Node (4-Bit Stride Engine)
typedef struct trie_node {
    char remote_vtep[32];           // Populated if a valid leaf route prefix terminates here
    uint32_t prefix_len;            // Tracked for checking nested rule precedence
    struct trie_node *child[STRIDE_SIZE]; // Array of 16 hardware branch references
} trie_node_t;

// --- GLOBAL ASIC MEMORY PROFILE ---
tcam_row_t TCAM_MEMORY[TCAM_MAX_ROWS];
int tcam_row_count = 0;

// Helper to instantiate empty trie nodes in ASIC SRAM simulation
trie_node_t* create_trie_node() {
    trie_node_t *node = (trie_node_t*)malloc(sizeof(trie_node_t));
    if (node) {
        memset(node->remote_vtep, 0, sizeof(node->remote_vtep));
        node->prefix_len = 0;
        for (int i = 0; i < STRIDE_SIZE; i++) {
            node->child[i] = NULL;
        }
    }
    return node;
}

// --- ARCHITECTURE 1: TCAM PARALLEL SIMULATION ---
void program_tcam_row(uint32_t tenant, const char *prefix, int cidr, const char *vtep) {
    if (tcam_row_count >= TCAM_MAX_ROWS) return;

    uint32_t ip_bin;
    inet_pton(AF_INET, prefix, &ip_bin);
    ip_bin = ntohl(ip_bin);

    // Formulate the Ternary mask layout: high bits are active match, lower bits are "Don't Care" (X)
    uint32_t mask = (cidr == 0) ? 0 : (~0X00) << (32 - cidr);

    TCAM_MEMORY[tcam_row_count] = (tcam_row_t){
        .tenant_id = tenant,
        .ip_data = ip_bin & mask,
        .ip_mask = mask,
        .prefix_len = cidr,
    };
    strncpy(TCAM_MEMORY[tcam_row_count].remote_vtep, vtep, 31);
    tcam_row_count++;
}

// Simulated Hardware Priority Encoder
// Simulates evaluating all memory grid lanes concurrently in 1 clock cycle
int query_tcam_hardware(uint32_t tenant, uint32_t lookup_ip, char *vtep_out) {
    int best_match_index = -1;
    uint32_t highest_prefix = 0;

    for (int i = 0; i < tcam_row_count; i++) {
        // Parallel check: Match Tenant ID AND evaluate matching bits matching the specific Ternary mask range
        if (TCAM_MEMORY[i].tenant_id == tenant && 
           (lookup_ip & TCAM_MEMORY[i].ip_mask) == TCAM_MEMORY[i].ip_data) {
            
            // Priority Encoder logic: Select the longest mask length matched natively
            if (TCAM_MEMORY[i].prefix_len >= highest_prefix) {
                highest_prefix = TCAM_MEMORY[i].prefix_len;
                best_match_index = i;
            }
        }
    }

    if (best_match_index != -1) {
        strcpy(vtep_out, TCAM_MEMORY[best_match_index].remote_vtep);
        return highest_prefix;
    }
    return -1; // Drop frame
}

// --- ARCHITECTURE 2: MULTI-BIT RADIX TRIE (ALGORITHMIC) ---
void insert_trie_route(trie_node_t *root, uint32_t ip, int cidr, const char *vtep) {
    trie_node_t *curr = root;
    // Iterate 4 bits at a time (8 strides total build a complete 32-bit layout)
    int remaining_bits = cidr;
    int shift = 28;

    while (remaining_bits > 0) {
        int index = (ip >> shift) & 0x0F; // Extract specific 4-bit chunk
        if (!curr->child[index]) {
            curr->child[index] = create_trie_node();
        }
        curr = curr->child[index];
        remaining_bits -= STRIDE_BITS;
        shift -= STRIDE_BITS;
    }
    // Set terminal lookup attributes at leaf node interface boundary
    strncpy(curr->remote_vtep, vtep, 31);
    curr->prefix_len = cidr;
}

// Algorithmic Pipelined Trie Query
int query_trie_hardware(trie_node_t *root, uint32_t lookup_ip, char *vtep_out) {
    trie_node_t *curr = root;
    int best_prefix = -1;
    int shift = 28;

    for (int step = 0; step < 8; step++) {
        int index = (lookup_ip >> shift) & 0x0F; // Extract current pipeline stage 4-bit pointer group
        if (!curr->child[index]) break;

        curr = curr->child[index];
        if (curr->prefix_len > 0) { // Keep updating tracking variable to maintain Longest Prefix Match stability
            strcpy(vtep_out, curr->remote_vtep);
            best_prefix = curr->prefix_len;
        }
        shift -= STRIDE_BITS;
    }
    return best_prefix;
}

// --- ARCHITECTURE 3: ECMP HASHING & CORES DISTRIBUTION ---
// Simulates hardware hashing to choose an optimal spine path dynamically
int execute_ecmp_hash(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, uint8_t proto) {
    // 5-Tuple Hardware XOR-Folding Hash computation simulation
    uint32_t hash = src_ip ^ dst_ip ^ ((src_port << 16) | dst_port) ^ proto;
    hash = ((hash >> 16) ^ hash) * 0x45d9f3b;
    hash = ((hash >> 16) ^ hash) * 0x45d9f3b;
    hash = (hash >> 16) ^ hash;
    return (hash % 4) + 1; // Balancing evenly across 4 Spine nodes (Spine-1 to Spine-4)
}

// --- UNIFIED ASIC PROCESSING PIPELINE ---
void asic_process_packet(uint32_t tenant, const char *src_ip_str, const char *dst_ip_str, 
                         uint16_t src_port, uint16_t dst_port, u_int8_t proto, trie_node_t *trie_root) {
    
    printf("\n[ASIC-PIPELINE] Ingesting Inbound Packet frame...\n");
    printf("   Metadata -> Tenant ID: %d | Proto: %d | Session: %s:%d -> %s:%d\n", 
           tenant, proto, src_ip_str, src_port, dst_ip_str, dst_port);

    uint32_t src_ip_bin, dst_ip_bin;
    inet_pton(AF_INET, src_ip_str, &src_ip_bin);
    inet_pton(AF_INET, dst_ip_str, &dst_ip_bin);
    src_ip_bin = ntohl(src_ip_bin);
    dst_ip_bin = ntohl(dst_ip_bin);

    char tcam_vtep[32] = {0};
    char trie_vtep[32] = {0};

    // Pipeline Step 1: Parallel TCAM Evaluation Loop
    int tcam_match_len = query_tcam_hardware(tenant, dst_ip_bin, tcam_vtep);
    
    // Pipeline Step 2: Algorithmic Multi-Bit Radix Trie Evaluation Loop
    int trie_match_len = query_trie_hardware(trie_root, dst_ip_bin, trie_vtep);

    if (tcam_match_len < 0 || trie_match_len < 0) {
        printf("   [!] PIPELINE DROP: Destination Route Lookup Missed. Discarding unroutable frame.\n");
        return;
    }

    printf("   [+] PIPELINE MATCH: LPM Resolved successfully!\n");
    printf("       -> TCAM Lookup Engine Verified Path Match Length: /%d -> Target VTEP: %s\n", tcam_match_len, tcam_vtep);
    printf("       -> Trie Lookup Engine Verified Path Match Length: /%d -> Target VTEP: %s\n", trie_match_len, trie_vtep);

    // Pipeline Step 3: ECMP Load-Balancing Execution
    int selected_spine = execute_ecmp_hash(src_ip_bin, dst_ip_bin, src_port, dst_port, proto);
    printf("   [+] PIPELINE ENCAPSULATION ENVELOPE GENERATED:\n");
    printf("       -> VXLAN Destination Encapsulation VTEP Core IP: %s\n", trie_vtep);
    printf("       -> ECMP Hashing Selection Result: Scheduled over Egress Link [SPINE NODE-%d]\n", selected_spine);
}

// Clean memory allocation pools 
void free_trie_memory(trie_node_t *node) {
    if (!node) return;
    for (int i = 0; i < STRIDE_SIZE; i++) {
        if (node->child[i]) free_trie_memory(node->child[i]);
    }
    free(node);
}

int main() {
    printf("[ASIC-INITIALIZE] Initializing TCAM and Multi-Bit SRAM Trie Engines...\n");
    trie_node_t *trie_root = create_trie_node();

    // Program Overlapping Routing Entries across Separate Virtual Network Profiles (Tenant 100 vs Tenant 200)
    // Tenant 100 (Corporate Dev Environment)
    program_tcam_row(100, "0.0.0.0", 0, "10.10.10.254");                      // Default Gate
    program_tcam_row(100, "142.251.0.0", 16, "10.10.10.10");                  // Broad route rule
    program_tcam_row(100, "142.251.151.0", 24, "10.10.10.99");                 // Longest specific match block
    
    uint32_t ip1, ip2, ip3;
    inet_pton(AF_INET, "0.0.0.0", &ip1);          insert_trie_route(trie_root, ntohl(ip1), 0, "10.10.10.254");
    inet_pton(AF_INET, "142.251.0.0", &ip2);      insert_trie_route(trie_root, ntohl(ip2), 16, "10.10.10.10");
    inet_pton(AF_INET, "142.251.151.0", &ip3);  insert_trie_route(trie_root, ntohl(ip3), 24, "10.10.10.99");

    // Tenant 200 (Corporate Production Isolation Profile) - Demonstrates identical IPs routing to different endpoints!
    program_tcam_row(200, "142.251.151.0", 24, "20.20.20.150");
    inet_pton(AF_INET, "142.251.151.0", &ip3);  insert_trie_route(trie_root, ntohl(ip3), 24, "20.20.20.150");

    // --- STREAM LIVE TEST PACKETS INTO PIPELINE ---
    
    // Packet 1: Tenant 100 requesting an execution targeting the nested /24 boundary
    asic_process_packet(100, "10.1.1.5", "142.251.151.119", 45678, 443, 6, trie_root);

    // Packet 2: Identical source/destination ports, but changing the source port slightly to show ECMP path shifting
    asic_process_packet(100, "10.1.1.5", "142.251.151.119", 49152, 443, 6, trie_root);

    // Packet 3: Tenant 200 requesting the *exact same address* - routes to a completely different corporate core VTEP!
    asic_process_packet(200, "10.2.1.5", "142.251.151.119", 45678, 443, 6, trie_root);

    free_trie_memory(trie_root);
    return 0;
}

