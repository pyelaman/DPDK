#ifndef ALKIRA_STATE_H
#define ALKIRA_STATE_H

#include "alkira_dpdk.h"
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_atomic.h>

/* Metadata entry block pinned to every concurrent live flow session */
typedef struct {
    uint64_t   packet_count;
    uint64_t   byte_count;
    uint64_t   last_seen_tsc;      // Used for tracking inactive session timeouts
    uint32_t   canonical_hash;     // Precomputed hash token signature
    uint64_t   timeout_duration;   // Dynamically adjusts depending on internal state transitions
    flow_key_t session_key;        // Cached structurally to enable structural deletion routines
    uint16_t   assigned_fw_port;   // Stored firewall path index to enforce stickiness
    uint16_t   egress_vni;         // Transit tenant boundary identification tag
    uint8_t    tcp_state;          // 0: SYN, 1: ESTABLISHED, 2: FIN/RST
    bool       is_active;
} __attribute__((aligned(64))) session_meta_t;

/* Global state controller abstraction layer */
typedef struct {
    struct rte_hash *hash_table_ctx;
    session_meta_t  *metadata_array; // Extracted array map utilizing DPDK's index returns
    uint32_t         max_sessions;
} alkira_state_engine_t;

#include <rte_atomic.h>

/* Formalized TCP Tracking States */
typedef enum {
    ALKIRA_TCP_STATE_SYN = 0,
    ALKIRA_TCP_STATE_ESTABLISHED,
    ALKIRA_TCP_STATE_FIN_WAIT,
    ALKIRA_TCP_STATE_CLOSED
} alkira_tcp_state_t;

/* Standard timeout buckets (in CPU clock cycles) mapped to current TSC ticks */
#define TIMEOUT_SYN_SECS         10
#define TIMEOUT_ESTABLISHED_SECS 1200  // 20 minutes
#define TIMEOUT_FIN_RST_SECS     5

extern alkira_state_engine_t state_engine;
extern volatile bool force_quit;

#endif

