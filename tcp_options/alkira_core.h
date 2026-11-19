#ifndef ALKIRA_CORE_H
#define ALKIRA_CORE_H

#include <stdint.h>
#include <stdbool.h>

#define VXLAN_PORT 4789
#define ALKIRA_MAX_FIREWALLS 8
#define ALKIRA_MSS_FLOOR 1360

/* 5-Tuple Structure for Session Tracking */
typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;
} __attribute__((packed)) flow_key_t;

/* Standard Protocol Header Mimics */
struct vxlan_hdr {
    uint32_t flags_vni; // 8-bit flags + 24-bit VNI
    uint32_t reserved;
} __attribute__((packed));

struct ip_hdr {
    uint8_t  ver_ihl;   // Version and Internet Header Length
    uint8_t  tos;
    uint16_t total_length;
    uint16_t id;
    uint16_t fragment_offset;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
} __attribute__((packed));

struct tcp_hdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint16_t data_offset_flags; // 4-bit data offset, 6-bit reserved, 6-bit flags
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;
} __attribute__((packed));

/* Firewall Node Definition for Service Chain */
typedef struct {
    uint32_t fw_ip;
    uint16_t fw_id;
    bool     is_alive;
} firewall_node_t;

#endif

