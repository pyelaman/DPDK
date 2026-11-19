#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

#define MAX_FIB_ENTRIES 10
#define MAX_ARP_ENTRIES 5

// Core Data Structures representing Router Memory Tables
typedef struct {
    uint32_t network;      // Subnet prefix in binary network order
    uint32_t netmask;      // Subnet mask in binary network order
    uint32_t mask_length;  // CIDR value (e.g., 24) used to evaluate prefix length hierarchy
    char next_hop_ip[16];  // Next Hop Router Interface IP
    char egress_if[8];     // Physical outbound interface name
} fib_entry_t;

typedef struct {
    char ip_addr[16];      // Key: IP Address of adjacent link interface
    uint8_t mac_addr[6];   // Value: Hardware Media Access Control Address
} arp_entry_t;

// Global Hardware Forwarding tables
fib_entry_t FIB_TABLE[MAX_FIB_ENTRIES];
arp_entry_t ARP_CACHE[MAX_ARP_ENTRIES];
int fib_count = 0;
int arp_count = 0;

// Initialize tables with a sample Multi-Cloud Core topology
void initialize_router_tables() {
    // 1. Populate Forwarding Information Base (FIB) - Simulating parsed RIB updates
    // Entries are intentionally added out of order to verify Longest Prefix Match sorting
    
    // Default Gateway (0.0.0.0/0)
    FIB_TABLE[0] = (fib_entry_t){0x00000000, 0x00000000, 0, "12.242.124.1", "eth0"}; 
    
    // Generic Carrier Transit Block (142.251.0.0/16)
    FIB_TABLE[1] = (fib_entry_t){htonl(0x8EAF0000), htonl(0xFFFF0000), 16, "32.130.26.1", "eth1"}; 
    
    // Highly Specific Cloud App Target Block (142.251.157.0/24)
    FIB_TABLE[2] = (fib_entry_t){htonl(0x8EAF9D00), htonl(0xFFFFFF00), 24, "32.130.25.168", "eth2"};
    
    fib_count = 3;

    // 2. Populate ARP Cache Table
    ARP_CACHE[0] = (arp_entry_t){"12.242.124.1", {0x00, 0x50, 0x56, 0xA1, 0xB2, 0xC3}};
    ARP_CACHE[1] = (arp_entry_t){"32.130.26.1",  {0x00, 0x50, 0x56, 0xBF, 0x22, 0x33}};
    ARP_CACHE[2] = (arp_entry_t){"32.130.25.168", {0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E}};
    arp_count = 3;
}

// LONGEST PREFIX MATCH (LPM) ALGORITHM
// Evaluates destination IPs against binary subnet definitions to extract the most specific path
int perform_longest_prefix_match(uint32_t dest_ip, fib_entry_t *matched_route) {
    int best_index = -1;
    uint32_t highest_prefix_length = 0;

    for (int i = 0; i < fib_count; i++) {
        // Bitwise AND operation to test if the destination IP falls within the current rule's boundary
        if ((dest_ip & FIB_TABLE[i].netmask) == FIB_TABLE[i].network) {
            // Tie-breaker: Always select the most specific mask length (Longest Prefix Match rule)
            if (FIB_TABLE[i].mask_length >= highest_prefix_length) {
                highest_prefix_length = FIB_TABLE[i].mask_length;
                best_index = i;
            }
        }
    }

    if (best_index != -1) {
        *matched_route = FIB_TABLE[best_index];
        return 0; // Route located successfully
    }
    return -1; // No route matched (Drop packet)
}

// ADDRESS RESOLUTION PROTOCOL (ARP) CACHE LOOKUP
// Resolves the physical layer MAC address mapped to the determined next-hop IP
int resolve_arp_hardware_address(const char *ip_addr, uint8_t *mac_out) {
    for (int i = 0; i < arp_count; i++) {
        if (strcmp(ARP_CACHE[i].ip_addr, ip_addr) == 0) {
            memcpy(mac_out, ARP_CACHE[i].mac_addr, 6);
            return 0;
        }
    }
    return -1; // ARP Cache Miss (Would trigger an active broadcast on physical wires in a live system)
}

// SIMULATED DATA PLANE PROCESSOR
void process_transit_packet(const char *dest_ip_str, int current_packet_ttl) {
    printf("\n[DATA-PLANE] Processing Inbound Traceroute Probe (Target: %s, Current TTL: %d)\n", dest_ip_str, current_packet_ttl);

    uint32_t dest_ip_bin;
    inet_pton(AF_INET, dest_ip_str, &dest_ip_bin);

    // Step 1: Decrement and evaluate TTL expiration status
    int next_ttl = current_packet_ttl - 1;
    if (next_ttl <= 0) {
        printf("[!] ACTION: TTL Expired in Transit (Hit 0). Generating ICMP Type 3 Code 4 back to source node.\n");
        return;
    }

    // Step 2: Query FIB using the Longest Prefix Match mechanism
    fib_entry_t route;
    if (perform_longest_prefix_match(dest_ip_bin, &route) < 0) {
        printf("[-] ACTION: Routing Drop. No viable routes found inside FIB table.\n");
        return;
    }

    printf("[+] FIB MATCH: Route found for target via %s/%d (Next Hop: %s, Egress IF: %s)\n",
           dest_ip_str, route.mask_length, route.next_hop_ip, route.egress_if);

    // Step 3: Check ARP table to construct the new Layer 2 Frame
    uint8_t dest_mac[6];
    if (resolve_arp_hardware_address(route.next_hop_ip, dest_mac) < 0) {
        printf("[!] ARP MISS: Next-hop IP %s not resolved. Buffering packet and firing ARP Request broadcast.\n", route.next_hop_ip);
        return;
    }

    // Step 4: Output the completed Layer 2 encapsulation transformation ready for serialization
    printf("[+] FRAME ENCAPSULATION SUCCESSFUL:\n");
    printf("    -> Decremented Packet TTL: %d\n", next_ttl);
    printf("    -> Assigned Outbound Port: %s\n", route.egress_if);
    printf("    -> Target Destination MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           dest_mac[0], dest_mac[1], dest_mac[2], dest_mac[3], dest_mac[4], dest_mac[5]);
}

int main() {
    initialize_router_tables();

    // Test Case 1: Packet targets an address that triggers the highly specific /24 rule
    process_transit_packet("142.251.157.119", 12);

    // Test Case 2: Packet triggers an intentionally expired hop step (mimicking traceroute intercept)
    process_transit_packet("142.251.157.119", 1);

    // Test Case 3: Packet targets a generic external network falling back to the /0 Default Route
    process_transit_packet("8.8.8.8", 5);

    return 0;
}

