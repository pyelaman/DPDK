#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define MAX_PREFIXES 100000

typedef struct {
    uint32_t active_underlay_vtep;
    uint32_t backup_underlay_vtep;
    uint32_t active_physical_egress_port;
} indirect_next_hop_t;

typedef struct {
    uint32_t destination_prefix;
    indirect_next_hop_t *inh_pointer; // DAG Pointer to shared indirect next hop record row
} prefix_route_t;

int main(void) {
    // 1. Establish Indirect Next-Hop mappings (Shared dependency state point)
    indirect_next_hop_t *shared_inh = malloc(sizeof(indirect_next_hop_t));
    shared_inh->active_underlay_vtep = 0x0A2FFF01;       // Primary Remote Leaf VTEP VNI Gateway
    shared_inh->backup_underlay_vtep = 0x0A2FFF02;       // Secondary Backup Remote VTEP Path
    shared_inh->active_physical_egress_port = 1;         // Primary Fiber Line port index
    
    // 2. Allocate and seed 100,000 unique tenant routes pointing to the shared record
    prefix_route_t *rib_table = calloc(MAX_PREFIXES, sizeof(prefix_route_t));
    for (uint32_t i = 0; i < MAX_PREFIXES; i++) {
        rib_table[i].destination_prefix = 0xAC100000 + i; // Simulated unique subnets
        rib_table[i].inh_pointer = shared_inh;
    }
    printf("[INFO] Allocated %d prefix routes dependent on 1 single \
            Indirect Next-Hop mapping record.\n", MAX_PREFIXES);
    
    // Test prefix verification state before underlay outage
    printf("[PRE-FAILOVER] Route[500]: Prefix=0x%X -> Routing via Active VTEP: 0x%X \
            on Egress Port: %u\n",
           rib_table[500].destination_prefix, 
           rib_table[500].inh_pointer->active_underlay_vtep,
           rib_table[500].inh_pointer->active_physical_egress_port);

    // 3. SIMULATED UNDERLAY FAILURE INTRUSION
    // IS-IS withdraws the primary link. The system shifts traffic by updating a 
    // single shared reference.
    printf("\n[!!! UNDERLAY ALARM !!!] IS-IS withdraws reachability \
            for VTEP 0x0A2FFF01 in 300ms...\n");
    
    // O(1) Atomic Swap Phase Execution 
    shared_inh->active_underlay_vtep = shared_inh->backup_underlay_vtep; // Switch to backup VTEP
    shared_inh->active_physical_egress_port = 2;                        // Switch to backup port
    
    printf("[CONVERGED] Invariant swap execution complete.\n\n");

    // Test prefix state evaluation directly after failure
    printf("[POST-FAILOVER] Route[500]: Prefix=0x%X -> Routing via Active VTEP: 0x%X \
            on Egress Port: %u\n",
           rib_table[500].destination_prefix, 
           rib_table[500].inh_pointer->active_underlay_vtep,
           rib_table[500].inh_pointer->active_physical_egress_port);
    printf("[SUCCESS] All %d prefixes converged instantly in O(1) time complexity.\n", MAX_PREFIXES);

    free(shared_inh);
    free(rib_table);
    return 0;
}

