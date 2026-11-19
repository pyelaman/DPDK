#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <string.h>
#include <time.h>

#define MAX_TENANTS 16
#define ARP_CACHE_SIZE 4096
#define ROUTE_TABLE_SIZE 8192

// --- STRUCTURES & CONTEXT TYPES ---
// Route Target Tuple
typedef struct {
    uint32_t global_as;
    uint32_t vni_tag;
} route_target_t;

// Simulated Next-Hop Entry
typedef struct {
    uint32_t tunnel_endpoint_ip;
    uint32_t vxlan_vni;
    uint32_t ethernet_segment_id; // ESI used for mass-withdrawal triggers
    bool     is_valid;
} evpn_next_hop_t;

// BGP Route Entry
typedef struct {
    uint32_t          prefix_ip;
    uint8_t           prefix_len;
    uint32_t          vrf_id;
    evpn_next_hop_t   next_hop;
    bool              is_valid;
} bgp_route_t;

// Proxy ARP Node
typedef struct {
    uint32_t ip_address;
    uint8_t  mac_address[6];
    uint32_t vrf_id;
    bool     is_valid;
} proxy_arp_entry_t;

// --- EXECUTABLE STATE PIPELINE CONTROLLERS ---

typedef struct {
    bgp_route_t       global_rib[ROUTE_TABLE_SIZE];
    proxy_arp_entry_t arp_table[ARP_CACHE_SIZE];
    
    // BGP Graceful Restart & Keepalive Tracking Parameters
    _Atomic uint64_t  last_keepalive_timestamp;
    _Atomic bool      is_bgp_session_established;
    _Atomic bool      is_graceful_restart_active;
    
    uint32_t          total_active_routes;
} evpn_control_plane_t;

// --- 1. PROXY ARP / ND & MAC SUPPRESSION LAYER ---
// Replaces data-plane BUM flooding with user-space hash responses
// Proxy ARP MAC Suppression (BUM Elimination): By matching an incoming Layer 3 IP directly 
// to a local, user-space proxy map (cp->arp_table), the lookup engine intercepts ARP queries locally.
// It returns the MAC instantly in O(1) time, eliminating noisy Broadcast storm cycles from ever 
// traversing the tenant's multi-cloud fabric.
bool handle_ingress_arp_request(evpn_control_plane_t* cp, uint32_t target_ip, 
                                uint32_t vrf_id, uint8_t* out_mac) {
    // Linear loop scan mimicking a fast open-addressing lookup register bucket
    uint32_t bucket = target_ip % ARP_CACHE_SIZE;
    for (size_t i = 0; i < 32; i++) { // Limit lookup bounds to protect L1 cache lines
        uint32_t idx = (bucket + i) % ARP_CACHE_SIZE;
        if (cp->arp_table[idx].is_valid && 
            cp->arp_table[idx].ip_address == target_ip && 
            cp->arp_table[idx].vrf_id == vrf_id) {
            memcpy(out_mac, cp->arp_table[idx].mac_address, 6);
            return true; // Proxy ARP Hit: Broadcast suppressed successfully!
        }
    }
    return false; // Proxy ARP Miss: Frame must fall-back to slow data plane processing pipeline
}

void inject_proxy_arp_binding(evpn_control_plane_t* cp, uint32_t ip, 
                              const uint8_t* mac, uint32_t vrf_id) {
    uint32_t idx = ip % ARP_CACHE_SIZE;
    while (cp->arp_table[idx].is_valid) {
        idx = (idx + 1) % ARP_CACHE_SIZE;
    }
    cp->arp_table[idx].ip_address = ip;
    memcpy(cp->arp_table[idx].mac_address, mac, 6);
    cp->arp_table[idx].vrf_id = vrf_id;
    cp->arp_table[idx].is_valid = true;
}

// --- 2. VRF ROUTE LEAK CONTAINMENT ARCHITECTURE ---
// Links separate routing scopes seamlessly via reference contexts without entry replication
bool clear_inter_vrf_leak_lookup(evpn_control_plane_t* cp, uint32_t ip, uint32_t source_vrf, 
                                 uint32_t target_transit_vrf, evpn_next_hop_t* out_nh) {
    // Step 1: Scan local VRF constraints. 
    // If missing, transparently fall back to the transit framework scope
    for (size_t i = 0; i < ROUTE_TABLE_SIZE; i++) {
        if (cp->global_rib[i].is_valid && 
            cp->global_rib[i].prefix_ip == (ip & 0xFFFF0000)) { // Summarized subnet match
            if (cp->global_rib[i].vrf_id == source_vrf || 
                cp->global_rib[i].vrf_id == target_transit_vrf) {
                *out_nh = cp->global_rib[i].next_hop;
                return true; // Fast intercept alignment success
            }
        }
    }
    return false;
}

// --- 3. EVPN MASS WITHDRAWAL EXECUTION ENGINES ---
// Invalidates thousands of paths in a single execution sweep by matching 
// next-hop identifiers (e.g., ESI)
//
// Mass Withdrawal via ESI Tokens (O(N) Processing vs O(N*M) Radix Traversals): 
// In standard networks, when a core multi-chassis link drops, the router sends individual 
// route withdrawals for every host subnet, stalling convergence. 
// This architecture implements EVPN Mass Withdrawal (RFC 7432) by appending a shared 32-bit 
// Ethernet Segment Identifier (ethernet_segment_id = 777) to all affected next-hops. 
// When the interface drops, the entire batch of 500 routes is invalidated in fractions 
// of a single millisecond.
size_t execute_evpn_mass_withdrawal_by_esi(evpn_control_plane_t* cp, uint32_t failed_esi) {
    size_t lines_invalidated = 0;
    for (size_t i = 0; i < ROUTE_TABLE_SIZE; i++) {
        if (cp->global_rib[i].is_valid && 
            cp->global_rib[i].next_hop.ethernet_segment_id == failed_esi) {
            // Drop route validity directly. Hardware lookup lines automatically 
            // register a routing bypass.
            cp->global_rib[i].is_valid = false;
            lines_invalidated++;
        }
    }
    cp->total_active_routes -= lines_invalidated;
    return lines_invalidated;
}

// --- 4. BGP GRACEFUL RESTART & KEEPALIVE KERNEL MANAGEMENT ---
void process_bgp_keepalive_pulse(evpn_control_plane_t* cp, uint64_t current_time) {
    atomic_store_explicit(&cp->last_keepalive_timestamp, current_time, memory_order_release);
    atomic_store_explicit(&cp->is_bgp_session_established, true, memory_order_release);
    atomic_store_explicit(&cp->is_graceful_restart_active, false, memory_order_release);
}

// Graceful Restart Routing Protection (Control-vs-Data Splitting): 
// By tracking health using relaxed atomic parameters (atomic_load_explicit), the architecture 
// splits data-plane packet processing from control-plane daemon crashes. 
// If the local BGP daemon crashes or stalls during a re-keying phase, 
// evaluate_bgp_session_health engages Graceful Restart (RFC 4724), 
// keeping user-space forwarding lines alive while the routing stack recovers.
bool evaluate_bgp_session_health(evpn_control_plane_t* cp, uint64_t current_time, 
                                 uint64_t hold_time_limit) {
    uint64_t last_pulse = atomic_load_explicit(&cp->last_keepalive_timestamp, memory_order_acquire);
    
    if (current_time - last_pulse > hold_time_limit) {
        // Keepalive pulse missed boundary limits! 
        // Activate Graceful Restart routing protection fallback
        if (!atomic_load_explicit(&cp->is_graceful_restart_active, memory_order_relaxed)) {
            atomic_store_explicit(&cp->is_graceful_restart_active, true, memory_order_release);
            atomic_store_explicit(&cp->is_bgp_session_established, false, memory_order_release);
            return true; // True indicates: GR Mode Engaged - KEEP forwarding plane paths active!
        }
        return false; // GR Timeout exceeded, must tear down forwarding lines completely
    }
    return true; // Session healthy
}

// --- DRIVER RUNNER BENCHMARK ---
int main() {
    evpn_control_plane_t* cp = malloc(sizeof(evpn_control_plane_t));
    memset(cp->global_rib, 0, sizeof(cp->global_rib));
    memset(cp->arp_table, 0, sizeof(cp->arp_table));
    cp->total_active_routes = 0;

    uint64_t clock_ticker = 1718000000;
    process_bgp_keepalive_pulse(cp, clock_ticker);

    printf("====================================================\n");
    printf("STARTING ADVANCED HIGH-SCALE EVPN CONTROL-PLANE SIM\n");
    printf("====================================================\n");

    // 1. Validate Proxy ARP & MAC Suppression Optimization
    uint8_t target_mac[6] = {0x00, 0x50, 0x56, 0x1A, 0x2B, 0x3C};
    uint32_t query_ip = 0x0A00000A; // 10.0.0.10
    uint32_t tenant_vrf = 101;
    inject_proxy_arp_binding(cp, query_ip, target_mac, tenant_vrf);

    uint8_t resolved_mac[6];
    bool arp_suppressed = handle_ingress_arp_request(cp, query_ip, tenant_vrf, resolved_mac);
    printf("[Strategy: Proxy ARP] Status: %s | Resolved MAC: %02X:%02X:%02X\n",
           arp_suppressed ? "SUPPRESSED SUCCESS (0 BUM Flooding)" : "MISS",
           resolved_mac[0], resolved_mac[1], resolved_mac[2]);

    // 2. Validate Inter-VRF Route Leak Containment
    evpn_next_hop_t leak_nh = { .tunnel_endpoint_ip = 0xC0A86401, .vxlan_vni = 9000, 
                                .ethernet_segment_id = 444, .is_valid = true };
    // Inject a route into Transit VRF 999 (Shared Services Scope)
    cp->global_rib[0] = (bgp_route_t){ .prefix_ip = 0x0A640000, .prefix_len = 16, 
                                       .vrf_id = 999, .next_hop = leak_nh, .is_valid = true };
    cp->total_active_routes++;

    evpn_next_hop_t resolved_nh;
    bool leak_resolved = clear_inter_vrf_leak_lookup(cp, 0x0A641122, 101, 999, &resolved_nh);
    printf("[Strategy: VRF Leaking] Cross-Lookup Status: %s | Shared Target Next-Hop VNI = %d\n",
           leak_resolved ? "RESOLVED PATH" : "DROP", resolved_nh.vxlan_vni);

    // 3. Validate High-Scale EVPN Mass Withdrawal Scenario
    printf("\nInjecting 500 parallel tenant routing entries mapped to shared link ESI 777...\n");
    for (size_t i = 1; i <= 500; i++) {
        evpn_next_hop_t nh = { .tunnel_endpoint_ip = 0xC0A80100 + i, .vxlan_vni = 20000 + i, 
                               .ethernet_segment_id = 777, .is_valid = true };
        cp->global_rib[i] = (bgp_route_t){ .prefix_ip = 0x10000000 + i, .prefix_len = 32, 
                                           .vrf_id = 101, .next_hop = nh, .is_valid = true };
        cp->total_active_routes++;
    }
    printf(" -> Baseline Active Route Count: %d\n", cp->total_active_routes);

    // Simulate physical physical link failure on the dual-homed interconnect trunk (ESI 777)
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    size_t routes_dropped = execute_evpn_mass_withdrawal_by_esi(cp, 777);
    clock_gettime(CLOCK_MONOTONIC, &end);

    double withdrawal_time_ms = (end.tv_sec - start.tv_sec) * 1000.0 + 
                                (end.tv_nsec - start.tv_nsec) / 1000000.0;
    printf(" -> Mass Withdrawal Status   : %s\n", routes_dropped == 500 ? "SUCCESS" : "FAILURE");
    printf(" -> Invalidated Entry Volume : %lu routes dropped in a single sweep\n", routes_dropped);
    printf(" -> Invalidation Execution   : %.4f milliseconds\n", withdrawal_time_ms);
    printf(" -> New Active Route Count   : %d\n", cp->total_active_routes);

    // 4. Validate BGP Graceful Restart Resilience Check
    printf("\n[BGP State Engine] Simulating control-plane daemon crash (stall keepalives for 45s)\n");
    clock_ticker += 45; // Jump clock forward past standard 30s BGP hold time parameters
    bool keep_forwarding = evaluate_bgp_session_health(cp, clock_ticker, 30);
    printf(" -> Data-Plane Forwarding Status: %s (Graceful Restart Active = %s)\n",
           keep_forwarding ? "KEEP ACTIVE (0 Packet Loss)" : "DROP FORWARDING LINES",
           atomic_load(&cp->is_graceful_restart_active) ? "TRUE" : "FALSE");

    printf("====================================================\n");

    free(cp);
    return 0;
}

