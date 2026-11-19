#include "alkira_core.h"

/* Incremental Internet Checksum Update (RFC 1624 structural implementation) */
static uint16_t update_checksum(uint16_t old_csum, uint16_t old_val, uint16_t new_val) {
    uint32_t csum = ~old_csum & 0xFFFF;
    csum += (~old_val & 0xFFFF) + new_val;
    csum = (csum >> 16) + (csum & 0xFFFF);
    csum += (csum >> 16);
    return (uint16_t)(~csum);
}

/* Decapsulates VXLAN wrapper and rewrites target TCP MSS parameter inline */
bool process_and_clamp_vxlan_packet(uint8_t *packet_buffer, uint32_t total_len) {
    // Offset calculation past standard headers: Outer Eth (14) + Outer IP (20) + Outer UDP (8)
    uint32_t vxlan_offset = 14 + 20 + 8;
    struct vxlan_hdr *v_hdr = (struct vxlan_hdr *)(packet_buffer + vxlan_offset);
    
    // Step in beyond VXLAN (8 bytes) + Inner Ethernet header boundary (14 bytes)
    uint32_t inner_ip_offset = vxlan_offset + sizeof(struct vxlan_hdr) + 14;
    struct ip_hdr *inner_ip = (struct ip_hdr *)(packet_buffer + inner_ip_offset);

    // Verify Inner layer payload is explicitly TCP
    if (inner_ip->protocol != 6) return false; 

    uint32_t inner_ip_len = (inner_ip->ver_ihl & 0x0F) * 4;
    uint32_t tcp_offset = inner_ip_offset + inner_ip_len;
    struct tcp_hdr *inner_tcp = (struct tcp_hdr *)(packet_buffer + tcp_offset);

    // Verify this is an active Handshake packet (SYN bit set, ACK flag can be optional)
    uint16_t flags = inner_tcp->data_offset_flags;
    bool is_syn = (flags & 0x0002) != 0; 
    if (!is_syn) return false; 

    uint32_t tcp_header_len = ((flags >> 12) & 0x0F) * 4;
    uint8_t *options_ptr = (uint8_t *)(packet_buffer + tcp_offset + sizeof(struct tcp_hdr));
    uint8_t *options_end = (uint8_t *)(packet_buffer + tcp_offset + tcp_header_len);

    // Parse the variable-length TCP options structure block
    while (options_ptr < options_end) {
        uint8_t opt_kind = options_ptr[0];
        if (opt_kind == 0) break; // End of Options list
        if (opt_kind == 1) {      // No-Operation padding byte
            options_ptr++;
            continue;
        }

        uint8_t opt_len = options_ptr[1];
        if (opt_len < 2 || (options_ptr + opt_len) > options_end) break;

        if (opt_kind == 2) { // Target Maximum Segment Size Option Found!
            uint16_t current_mss = (options_ptr[2] << 8) | options_ptr[3];
            
            if (current_mss > ALKIRA_MSS_FLOOR) {
                uint16_t legacy_mss_raw = current_mss;
                uint16_t clamped_mss = ALKIRA_MSS_FLOOR;

                // Overwrite the payload memory block inline
                options_ptr[2] = (uint8_t)(clamped_mss >> 8);
                options_ptr[3] = (uint8_t)(clamped_mss & 0xFF);

                // Update TCP L4 Checksum incrementally to bypass full payload loop calculation
                inner_tcp->checksum = update_checksum(inner_tcp->checksum, legacy_mss_raw, clamped_mss);
                return true; // Clamping successfully performed
            }
        }
        options_ptr += opt_len;
    }
    return false;
}

