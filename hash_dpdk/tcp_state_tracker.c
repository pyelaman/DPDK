#include "alkira_state.h"

/* Processes incoming flag vectors to calculate the dynamic lifecycle of the flow */
void update_tcp_state_machine(session_meta_t *meta, const struct rte_tcp_hdr *tcp, uint64_t hertz_freq) {
    uint8_t flags = tcp->tcp_flags;
    
    // Quick handle for Reset conditions
    if (unlikely(flags & RTE_TCP_RST_FLAG)) {
        meta->tcp_state = ALKIRA_TCP_STATE_CLOSED;
        meta->timeout_duration = TIMEOUT_FIN_RST_SECS * hertz_freq;
        return;
    }

    switch (meta->tcp_state) {
        case ALKIRA_TCP_STATE_SYN:
            if ((flags & RTE_TCP_SYN_FLAG) && (flags & RTE_TCP_ACK_FLAG)) {
                // Handshake progression caught
                meta->tcp_state = ALKIRA_TCP_STATE_SYN; 
            } else if (flags & RTE_TCP_ACK_FLAG) {
                meta->tcp_state = ALKIRA_TCP_STATE_ESTABLISHED;
                meta->timeout_duration = TIMEOUT_ESTABLISHED_SECS * hertz_freq;
            }
            break;

        case ALKIRA_TCP_STATE_ESTABLISHED:
            if (flags & RTE_TCP_FIN_FLAG) {
                meta->tcp_state = ALKIRA_TCP_STATE_FIN_WAIT;
                meta->timeout_duration = TIMEOUT_FIN_RST_SECS * hertz_freq;
            }
            break;

        case ALKIRA_TCP_STATE_FIN_WAIT:
            if (flags & RTE_TCP_ACK_FLAG) {
                meta->tcp_state = ALKIRA_TCP_STATE_CLOSED;
                meta->timeout_duration = TIMEOUT_FIN_RST_SECS * hertz_freq;
            }
            break;

        default:
            break;
    }
}

