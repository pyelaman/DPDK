#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define HASH_TABLE_SIZE 1024

// Flyweight Pattern Structure for Path Attributes
typedef struct attr_block {
    char as_path[256];
    uint32_t route_target;
    uint32_t ref_count;
    struct attr_block *next; // Chaining for collisions
} attr_block_t;

attr_block_t* hash_table[HASH_TABLE_SIZE];

// Simple, fast string hashing function
uint32_t generate_attribute_hash(const char *as_path, uint32_t rt) {
    uint32_t hash = 5381;
    while (*as_path) {
        hash = ((hash << 5) + hash) + *as_path++;
    }
    hash = ((hash << 5) + hash) + rt;
    return hash % HASH_TABLE_SIZE;
}

attr_block_t* intern_attributes(const char *as_path, uint32_t rt) {
    uint32_t slot = generate_attribute_hash(as_path, rt);
    attr_block_t *entry = hash_table[slot];
    
    // Look for matching attribute blocks in the table
    while (entry != NULL) {
        if (strcmp(entry->as_path, as_path) == 0 && entry->route_target == rt) {
            entry->ref_count++; // Hit found! Increment reference counter.
            return entry;
        }
        entry = entry->next;
    }
    
    // Miss: Allocate a new shared attribute block
    attr_block_t *new_block = malloc(sizeof(attr_block_t));
    strncpy(new_block->as_path, as_path, sizeof(new_block->as_path));
    new_block->route_target = rt;
    new_block->ref_count = 1;
    new_block->next = hash_table[slot];
    hash_table[slot] = new_block;
    
    return new_block;
}

int main(void) {
    memset(hash_table, 0, sizeof(hash_table));
    
    printf("--- Interning Path Attributes for Multiple Prefixes ---\n");
    // Prefix 1 and Prefix 2 share identical BGP parameters
    attr_block_t *prefix1_attr = intern_attributes("65001_64512_1102", 20050);
    attr_block_t *prefix2_attr = intern_attributes("65001_64512_1102", 20050); 
    // Prefix 3 has unique attributes
    attr_block_t *prefix3_attr = intern_attributes("65001_69099_4412", 20050);

    printf("Block 1 Address: %p (Ref Count: %u)\n", (void*)prefix1_attr, prefix1_attr->ref_count);
    printf("Block 2 Address: %p (Ref Count: %u) <--- Exact duplicate match used zero extra RAM!\n", 
            (void*)prefix2_attr, prefix2_attr->ref_count);
    printf("Block 3 Address: %p (Ref Count: %u)\n", (void*)prefix3_attr, prefix3_attr->ref_count);

    // Cleanup memory
    for(int i=0; i<HASH_TABLE_SIZE; i++) {
        attr_block_t *curr = hash_table[i];
        while(curr) {
            attr_block_t *tmp = curr;
            curr = curr->next;
            free(tmp);
        }
    }
    return 0;
}

