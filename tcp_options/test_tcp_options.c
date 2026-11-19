#include <stdio.h>
#include <string.h>
#include "alkira_core.h"

// External references to our modular architectural layers
extern uint16_t enforce_traffic_symmetry(const flow_key_t *raw_flow, uint16_t local_cxp_id);
extern void initialize_firewall_pool(void);
extern uint8_t select_firewall_instance(const flow_key_t *raw_flow);
extern bool process_and_clamp_vxlan_packet(uint8_t *packet_buffer, uint32_t total_len);

int main(void) {
    initialize_firewall_pool();
    printf("[ALKIRA PIPELINE INITIALIZED] Data plane components ready.\n");

    // Initialize an empty memory block simulating an incoming VXLAN frame 
    uint8_t simulated_packet[256];
    memset(simulated_packet, 0, sizeof(simulated_packet));

    // Construct a mock inner TCP SYN stream (AWS instance -> Azure node target)
    uint32_t inner_ip_pos = 14 + 20 + 8 + 8 + 14; // Outer Eth + IP + UDP + VXLAN + Inner Eth
    struct ip_hdr *ip = (struct ip_hdr *)(simulated_packet + inner_ip_pos);
    ip->ver_ihl = 0x45; // IPv4, 20-byte standard header length
    ip->protocol = 6;   // TCP Protocol Identification
    ip->src_ip = 0x0A000002; // AWS Node: 10.0.0.2
    ip->dst_ip = 0x14000002; // Azure Node: 20.0.0.2

    uint32_t inner_tcp_pos = inner_ip_pos + 20;
    struct tcp_hdr *tcp = (struct tcp_hdr *)(simulated_packet + inner_tcp_pos);
    tcp->src_port = 0xEA60; // Port 60000
    tcp->dst_port = 0x01BB; // Port 443
    tcp->data_offset_flags = (0x6000 | 0x0002); // 24-byte TCP header size (offset=6), SYN flag set

    // Append standard TCP Option Kind=2 (MSS Size field descriptor)
    uint8_t *options = (uint8_t *)(simulated_packet + inner_tcp_pos + sizeof(struct tcp_hdr));
    options[0] = 2;    // Option Kind: MSS
    options[1] = 4;    // Length: 4 bytes
    options[2] = 0x05; // 0x05B4 sets default payload window limit to 1460 bytes
    options[3] = 0xB4;

    // --- EXECUTE STACK PROCESSING TRANSIT LAYER ---
    flow_key_t live_flow = {
        .src_ip = ip->src_ip, .dst_ip = ip->dst_ip,
        .src_port = tcp->src_port, .dst_port = tcp->dst_port,
        .protocol = ip->protocol
    };

    // 1. Enforce Routing Symmetry Node Selection
    uint16_t assigned_cxp = enforce_traffic_symmetry(&live_flow, 442);
    printf(">> Step 1 (Symmetric Director): Flow routed to CXP Blade ID [%d]\n", assigned_cxp);

    // 2. Select Firewalls via Pinned Balanced Token Hashing
    uint8_t fw_index = select_firewall_instance(&live_flow);
    printf(">> Step 2 (Service Load Balancer): Pinned Flow to Security Instance Index [%d]\n", fw_index);

    // 3. Apply Inline Multi-Cloud Overlay MSS Clamping Modification
    bool clamped = process_and_clamp_vxlan_packet(simulated_packet, sizeof(simulated_packet));
    
    if (clamped) {
        uint16_t rewritten_mss = (options[2] << 8) | options[3];
        printf(">> Step 3 (MSS Clamper): Success. TCP Option Overwritten. New Segment Value = [%d]\n", rewritten_mss);
    } else {
        printf(">> Step 3 (MSS Clamper): Execution bypassed or error flag thrown.\n");
    }

    return 0;
}

