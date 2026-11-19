#include "alkira_state.h"
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_cycles.h>

#define MILLION_SESSIONS 4000000 // Configured setup capacity boundary scale

alkira_state_engine_t state_engine;

/* Configures the high-performance lockless lookup table matrix */
bool initialize_alkira_session_table(void) {
    char name[32];
    snprintf(name, sizeof(name), "alkira_flow_table_%u", rte_socket_id());

    struct rte_hash_parameters hash_params = {
        .name = name,
        .entries = MILLION_SESSIONS,
        .key_len = sizeof(flow_key_t),
        .hash_func = rte_jhash,
        .hash_func_init_val = 0xDEADC0DE,
        .socket_id = (int)rte_socket_id(),
        /* Multi-writer / multi-reader concurrancy configuration flags */
        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF | 
                      RTE_HASH_EXTRA_FLAGS_MULTI_WRITER_ADD
    };

    state_engine.hash_table_ctx = rte_hash_create(&hash_params);
    if (state_engine.hash_table_ctx == NULL) {
        return false; // Table allocation failed
    }

    // Allocate contiguous array pool matching maximum index limits
    state_engine.metadata_array = rte_zmalloc_socket(
        "session_meta_pool", 
        sizeof(session_meta_t) * MILLION_SESSIONS, 
        RTE_CACHE_LINE_SIZE, 
        rte_socket_id()
    );

    if (state_engine.metadata_array == NULL) {
        rte_hash_free(state_engine.hash_table_ctx);
        return false;
    }

    state_engine.max_sessions = MILLION_SESSIONS;
    return true;
}

/* Performs multi-core safe inline lookup and handles dynamic registration */
session_meta_t *get_or_create_session(const flow_key_t *c_key, uint16_t default_fw_port, bool *is_new_flow) {
    *is_new_flow = false;
    int32_t lookup_index = rte_hash_lookup(state_engine.hash_table_ctx, (const void *)c_key);

    if (likely(lookup_index >= 0)) {
        session_meta_t *meta = &state_engine.metadata_array[lookup_index];
        meta->last_seen_tsc = rte_get_tsc_cycles();
        return meta;
    }

    if (unlikely(lookup_index == -ENOENT)) {
        int32_t free_slot_index = rte_hash_add_key(state_engine.hash_table_ctx, (const void *)c_key);
        if (unlikely(free_slot_index < 0)) return NULL;

        session_meta_t *meta = &state_engine.metadata_array[free_slot_index];

        // Cache the structural index verification key explicitly for GC access operations
        meta->session_key = *c_key;
        meta->packet_count = 1;
        meta->last_seen_tsc = rte_get_tsc_cycles();
        meta->timeout_duration = TIMEOUT_SYN_SECS * rte_get_tsc_hz(); // Initialize with shorter SYN lifecycle 
								      // timeout values
        meta->assigned_fw_port = default_fw_port;
        meta->tcp_state = ALKIRA_TCP_STATE_SYN;
        meta->is_active = true;

        *is_new_flow = true;
        return meta;
    }
    return NULL;
}
