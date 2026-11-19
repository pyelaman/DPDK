#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct {
    uint32_t next_hop;
    uint32_t local_pref;
    uint32_t med;
} bgp_attr_t;

typedef struct radix_node {
    struct radix_node *child[2];
    bool is_valid_route;
    uint32_t prefix;
    uint32_t mask_len;
    bgp_attr_t best_path;
} radix_node_t;

radix_node_t* create_node(void) {
    return (radix_node_t*)calloc(1, sizeof(radix_node_t));
}

// Compare new path vs current path in O(1) time
bool evaluate_best_path_incremental(bgp_attr_t *current, bgp_attr_t *new_path) {
    if (new_path->local_pref > current->local_pref) return true;
    if (new_path->local_pref < current->local_pref) return false;
    if (new_path->med < current->med) return true; // Lower MED is preferred
    return false;
}

void insert_or_update_prefix(radix_node_t *root, uint32_t prefix, uint32_t mask_len, 
                             bgp_attr_t new_route) {
    radix_node_t *curr = root;
    for (uint32_t i = 0; i < mask_len; i++) {
        uint32_t bit = (prefix >> (31 - i)) & 1;
        if (!curr->child[bit]) {
            curr->child[bit] = create_node();
        }
        curr = curr->child[bit];
    }
    
    if (!curr->is_valid_route) {
        curr->is_valid_route = true;
        curr->prefix = prefix;
        curr->mask_len = mask_len;
        curr->best_path = new_route;
        printf("[INSERT] First path for %u.%u.%u.%u/%d setup via Next-Hop: 0x%X\n",
               (prefix>>24)&0xFF, (prefix>>16)&0xFF, (prefix>>8)&0xFF, prefix&0xFF, 
               mask_len, new_route.next_hop);
    } else {
        // Run O(1) Incremental Best-Path Execution
        if (evaluate_best_path_incremental(&curr->best_path, &new_route)) {
            printf("[UPDATE] Prefix %u.%u.%u.%u/%d updated path preference to Next-Hop: 0x%X\n",
                   (prefix>>24)&0xFF, (prefix>>16)&0xFF, (prefix>>8)&0xFF, prefix&0xFF, 
                   mask_len, new_route.next_hop);
            curr->best_path = new_route;
        } else {
            printf("[REJECT] New path to %u.%u.%u.%u/%d inferior to current best path.\n",
                   (prefix>>24)&0xFF, (prefix>>16)&0xFF, (prefix>>8)&0xFF, prefix&0xFF, mask_len);
        }
    }
}

int main(void) {
    radix_node_t *root = create_node();
    uint32_t target_prefix = 0x0A000000; // 10.0.0.0
    
    bgp_attr_t path1 = { .next_hop = 0x11111111, .local_pref = 100, .med = 50 };
    bgp_attr_t path2 = { .next_hop = 0x22222222, .local_pref = 200, .med = 20 }; // Better local pref
    bgp_attr_t path3 = { .next_hop = 0x33333333, .local_pref = 200, .med = 80 }; // Worse MED
    
    insert_or_update_prefix(root, target_prefix, 24, path1);
    insert_or_update_prefix(root, target_prefix, 24, path2);
    insert_or_update_prefix(root, target_prefix, 24, path3);
    
    return 0;
}

