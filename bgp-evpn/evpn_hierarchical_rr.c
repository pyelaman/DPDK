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

typedef struct {
    uint32_t tunnel_endpoint_ip;
    uint32_t vxlan_vni;
    uint32_t ethernet_segment_id; // ESI used for mass-withdrawal triggers
    bool     is_valid;
} evpn_next_hop_t;

typedef struct {
    uint32_t          prefix_ip;
    uint8_t           prefix_len;
    uint32_t          vrf_id;
    evpn_next_hop_t   next_hop;
    uint64_t          route_target_tenant;
    bool              is_valid;
} bgp_route_t;

typedef struct {
    uint32_t ip_address;
    uint8_t  mac_address[6];
    uint32_t vrf_id;
    bool     is_valid;
} proxy_arp_entry_t;

// --- STRATEGY: HIERARCHICAL ROUTE REFLECTOR SHARDS ---
// "How to partition Route Reflectors so that a single cluster crash does not drop the 
// entire multi-tenant cloud fabric?"
// We use the strategy Cluster Sharding by Tenant RT Ranges by allocating localized 
// Regional Cluster IDs that act as the first-tier aggregation layer, 
// which then route through a Global Transit RR Mesh
typedef struct {
    uint32_t cluster_id;
    uint64_t tenant_rt_start;
    uint64_t tenant_rt_end;
    uint32_t active_peer_count;
} rr_cluster_shard_t;

typedef struct {
    bgp_route_t          global_rib[ROUTE_TABLE_SIZE];
    proxy_arp_entry_t    arp_table[ARP_CACHE_SIZE];
    rr_cluster_shard_t   rr_shards[4]; // Supported sharded clusters
    
    _Atomic uint64_t     last_keepalive_timestamp;
    _Atomic bool         is_bgp_session_established;
    _Atomic bool         is_graceful_restart_active;
    
    uint32_t             total_active_routes;
} evpn_control_plane_t;

// --- 1. HIERARCHICAL RR CLUSTER ROUTING ENGINE ---
// Determines if a cluster shard is responsible for reflecting a specific tenant route
bool route_reflect_shard_decision(const evpn_control_plane_t* cp, uint32_t cluster_id, 
                                  uint64_t route_target) {
    for (size_t i = 0; i < 4; i++) {
        if (cp->rr_shards[i].cluster_id == cluster_id) {
            // Check if the Route Target falls inside this shard's ownership zone
            if (route_target >= cp->rr_shards[i].tenant_rt_start && 
                route_target <= cp->rr_shards[i].tenant_rt_end) {
                return true; // Shard processes this tenant route
            }
        }
    }
    return false; // Ignored by this shard cluster to optimize CPU cycles
}

// --- 2. PROXY ARP / ND & MAC SUPPRESSION LAYER ---
bool handle_ingress_arp_request(evpn_control_plane_t* cp, uint32_t target_ip, 
                                uint32_t vrf_id, uint8_t* out_mac) {
    uint32_t bucket = target_ip % ARP_CACHE_SIZE;
    for (size_t i = 0; i < 32; i++) { 
        uint32_t idx = (bucket + i) % ARP_CACHE_SIZE;
        if (cp->arp_table[idx].is_valid && 
            cp->arp_table[idx].ip_address == target_ip && 
            cp->arp_table[idx].vrf_id == vrf_id) {
            memcpy(out_mac, cp->arp_table[idx].mac_address, 6);
            return true; // Suppressed broadcast!
        }
    }
    return false;
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

// --- 3. VRF ROUTE LEAK CONTAINMENT ARCHITECTURE ---
bool clear_inter_vrf_leak_lookup(evpn_control_plane_t* cp, uint32_t ip, uint32_t source_vrf, 
                                 uint32_t target_transit_vrf, evpn_next_hop_t* out_nh) {
    for (size_t i = 0; i < ROUTE_TABLE_SIZE; i++) {
        if (cp->global_rib[i].is_valid && cp->global_rib[i].prefix_ip == (ip & 0xFFFF0000)) { 
            if (cp->global_rib[i].vrf_id == source_vrf || 
                cp->global_rib[i].vrf_id == target_transit_vrf) {
                *out_nh = cp->global_rib[i].next_hop;
                return true;
            }
        }
    }
    return false;
}

// --- 4. EVPN MASS WITHDRAWAL SCENARIO ---
size_t execute_evpn_mass_withdrawal_by_esi(evpn_control_plane_t* cp, uint32_t failed_esi) {
    size_t lines_invalidated = 0;
    for (size_t i = 0; i < ROUTE_TABLE_SIZE; i++) {
        if (cp->global_rib[i].is_valid && 
            cp->global_rib[i].next_hop.ethernet_segment_id == failed_esi) {
            cp->global_rib[i].is_valid = false;
            lines_invalidated++;
        }
    }
    cp->total_active_routes -= lines_invalidated;
    return lines_invalidated;
}

// --- 5. BGP GRACEFUL RESTART & KEEPALIVE TIMERS ---
void process_bgp_keepalive_pulse(evpn_control_plane_t* cp, uint64_t current_time) {
    atomic_store_explicit(&cp->last_keepalive_timestamp, current_time, memory_order_release);
    atomic_store_explicit(&cp->is_bgp_session_established, true, memory_order_release);
    atomic_store_explicit(&cp->is_graceful_restart_active, false, memory_order_release);
}

bool evaluate_bgp_session_health(evpn_control_plane_t* cp, uint64_t current_time, 
                                 uint64_t hold_time_limit) {
    uint64_t last_pulse = atomic_load_explicit(&cp->last_keepalive_timestamp, memory_order_acquire);
    
    if (current_time - last_pulse > hold_time_limit) {
        if (!atomic_load_explicit(&cp->is_graceful_restart_active, memory_order_relaxed)) {
            atomic_store_explicit(&cp->is_graceful_restart_active, true, memory_order_release);
            atomic_store_explicit(&cp->is_bgp_session_established, false, memory_order_release);
            return true; // Keep forwarding path active!
        }
        return false;
    }
    return true; 
}

// --- MAIN SYSTEM EXECUTION ---
int main() {
    evpn_control_plane_t* cp = malloc(sizeof(evpn_control_plane_t));
    memset(cp->global_rib, 0, sizeof(cp->global_rib));
    memset(cp->arp_table, 0, sizeof(cp->arp_table));
    cp->total_active_routes = 0;

    // Initialize Sharded Route Reflector Clusters
    cp->rr_shards[0] = (rr_cluster_shard_t){ .cluster_id = 10001, .tenant_rt_start = 1,
                                             .tenant_rt_end = 500 };
    cp->rr_shards[1] = (rr_cluster_shard_t){ .cluster_id = 10002, .tenant_rt_start = 501, 
                                             .tenant_rt_end = 1000 };

    uint64_t clock_ticker = 1718000000;
    process_bgp_keepalive_pulse(cp, clock_ticker);

    printf("====================================================\n");
    printf("STARTING ADVANCED HIGH-SCALE HIERARCHICAL EVPN SIM\n");
    printf("====================================================\n");

    // Test 1: Hierarchical Route Reflector Cluster Filtering
    uint64_t tenant_a_rt = 250;  // Managed by Shard 1
    uint64_t tenant_b_rt = 750;  // Managed by Shard 2
    
    bool shard1_reflects_a = route_reflect_shard_decision(cp, 10001, tenant_a_rt);
    bool shard1_reflects_b = route_reflect_shard_decision(cp, 10001, tenant_b_rt);
    
    printf("[Strategy: Hierarchical RR Cluster 10001]\n");
    printf(" -> Reflect Tenant RT 250 (Zone 1) : %s\n", 
            shard1_reflects_a ? "ACCEPTED (Reflecting to clients)" : "IGNORED");
    printf(" -> Reflect Tenant RT 750 (Zone 2) : %s\n", 
            shard1_reflects_b ? "ACCEPTED" : "MUTED (CPU Cycles Saved)");

    // Test 2: Proxy ARP MAC Suppression
    uint8_t target_mac[6] = {0x00, 0x50, 0x56, 0x1A, 0x2B, 0x3C};
    uint32_t query_ip = 0x0A00000A; // 10.0.0.10
    uint32_t tenant_vrf = 101;
    inject_proxy_arp_binding(cp, query_ip, target_mac, tenant_vrf);

    uint8_t resolved_mac[6];
    bool arp_suppressed = handle_ingress_arp_request(cp, query_ip, tenant_vrf, resolved_mac);
    printf("\n[Strategy: Proxy ARP & Neighbor Suppression]\n");
    printf(" -> Status: %s | Resolved MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           arp_suppressed ? "SUPPRESSED SUCCESS (0 Broadcast Flooding)" : "MISS",
           resolved_mac[0], resolved_mac[1], resolved_mac[2], resolved_mac[3], 
           resolved_mac[4], resolved_mac[5]);

    // Test 3: Inter-VRF Route Leak Containment
    evpn_next_hop_t leak_nh = { .tunnel_endpoint_ip = 0xC0A86401, .vxlan_vni = 9000, 
                                .ethernet_segment_id = 444, .is_valid = true };
    cp->global_rib[0] = (bgp_route_t){ .prefix_ip = 0x0A640000, .prefix_len = 16, 
                                       .vrf_id = 999, .next_hop = leak_nh, .is_valid = true };
    cp->total_active_routes++;

    evpn_next_hop_t resolved_nh;
    bool leak_resolved = clear_inter_vrf_leak_lookup(cp, 0x0A641122, 101, 999, &resolved_nh);
    printf("\n[Strategy: VRF Route Leaking / Service Chain Containment]\n");
    printf(" -> Cross-Lookup Status: %s | Shared Transit VNI Target = %d\n",
           leak_resolved ? "RESOLVED VIA TRANST CONTEXT" : "DROP", resolved_nh.vxlan_vni);

    // Test 4: EVPN Mass Withdrawal Scenario
    for (size_t i = 1; i <= 500; i++) {
        evpn_next_hop_t nh = { .tunnel_endpoint_ip = 0xC0A80100 + i, .vxlan_vni = 20000 + i, 
                               .ethernet_segment_id = 777, .is_valid = true };
        cp->global_rib[i] = (bgp_route_t){ .prefix_ip = 0x10000000 + i, .prefix_len = 32, 
                                           .vrf_id = 101, .next_hop = nh, .is_valid = true };
        cp->total_active_routes++;
    }
    printf("\n[Strategy: EVPN Mass Withdrawal at Scale]\n");
    printf(" -> Baseline Active Route Pool: %d\n", cp->total_active_routes);

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    size_t routes_dropped = execute_evpn_mass_withdrawal_by_esi(cp, 777);
    clock_gettime(CLOCK_MONOTONIC, &end);

    double withdrawal_time_ms = (end.tv_sec - start.tv_sec) * 1000.0 + 
                                (end.tv_nsec - start.tv_nsec) / 1000000.0;
    printf(" -> Invalidation Status       : %s (%lu routes dropped)\n", 
            routes_dropped == 500 ? "SUCCESS" : "FAILURE", routes_dropped);
    printf(" -> Execution Time Total       : %.4f ms\n", withdrawal_time_ms);
    printf(" -> Remaining Active Routes    : %d\n", cp->total_active_routes);

    // Test 5: BGP Graceful Restart Resilience Check
    printf("\n[Strategy: BGP Keepalive & Graceful Restart]\n");
    clock_ticker += 45; // Exceed standard 30-second hold timer limits
    bool keep_forwarding = evaluate_bgp_session_health(cp, clock_ticker, 30);
    printf(" -> Control Plane Crash Status : Keepalive Pulse Missed\n");
    printf(" -> Forwarding Plane Execution : %s (Graceful Restart Engine = %s)\n",
            keep_forwarding ? "KEEP ACTIVE (0 Data Loss)" : "TEAR DOWN INTERFACES",
    atomic_load(&cp->is_graceful_restart_active) ? "ENGAGED" : "OFF");
    printf("====================================================\n");
    free(cp);
    return 0;
}
