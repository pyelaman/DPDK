#ifndef DATAPLANE_STRUCTS_H
#define DATAPLANE_STRUCTS_H

#include <stdint.h>
#include <rte_common.h>
#include <rte_ether.h>

/* The 5-Tuple Connection Tracking Key */
struct __rte_packed_begin flow_key {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;
    uint8_t  pad[3]; /* Padding to align structure nicely */
} __rte_packed_end;

/* TCP Firewall State Engine Flags */
typedef enum {
    TCP_STATE_NONE = 0,
    TCP_STATE_SYN_SENT,
    TCP_STATE_SYN_RECEIVED,
    TCP_STATE_ESTABLISHED,
    TCP_STATE_FIN_WAIT,
    TCP_STATE_CLOSED
} tcp_state_t;

/* Action verdicts */
#define VERDICT_DROP    0
#define VERDICT_FORWARD 1

/* Connection tracking state entry, explicitly aligned to CPU cache lines */
struct __rte_cache_aligned flow_entry {
    struct flow_key key;
    uint32_t nat_src_ip;
    uint16_t nat_src_port;
    uint8_t  verdict;
    uint64_t total_packets;
    uint64_t total_bytes;
    uint64_t last_active_timestamp; /* CPU TSC cycles at last packet match */

    /* Stateful Tracking Layer */
    tcp_state_t state;
    uint32_t client_next_seq;
    uint32_t server_next_seq;
};

#endif

