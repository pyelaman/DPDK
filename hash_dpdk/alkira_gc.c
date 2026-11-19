#include "alkira_state.h"
#include <rte_cycles.h>
#include <rte_lcore.h>

#define GC_BATCH_SWEEP_SIZE 512
#define GC_SLEEP_MS 20

/* Background scavenger runtime loop mapping */
int async_gc_sweep_thread(__attribute__((unused)) void *arg) {
    uint32_t next_position = 0;
    const void *extracted_key;
    void *data_ptr;
    uint64_t tsc_hz = rte_get_tsc_hz();

    printf("[ALKIRA GC ENGINE] Asynchronous scavenger active on LCORE %u.\n", rte_lcore_id());

    while (!force_quit) {
        uint64_t current_tsc = rte_get_tsc_cycles();
        uint32_t processed_count = 0;

        /* Iterates across a strict allocation block using continuous offset tracking pointers */
        while (processed_count < GC_BATCH_SWEEP_SIZE) {
            int32_t position_index = rte_hash_iterate(
                state_engine.hash_table_ctx, 
                &extracted_key, 
                &data_ptr, 
                &next_position
            );

            // Break loop if the table iteration reaches the end
            if (unlikely(position_index < 0)) {
                next_position = 0; // Reset scanner boundary position tracker for the next iteration loop
                break;
            }

            session_meta_t *meta = &state_engine.metadata_array[position_index];

            if (meta->is_active) {
                // Determine if elapsed execution cycles exceed designated duration constraints
                if ((current_tsc - meta->last_seen_tsc) > meta->timeout_duration) {
                    
                    /* Execute structural atomic deletion out from the primary context tracking framework */
                    int32_t deletion_status = rte_hash_del_key(state_engine.hash_table_ctx, &meta->session_key);
                    
                    if (likely(deletion_status >= 0)) {
                        // Mark data block slots as free and completely clean metrics
                        meta->is_active = false;
                        meta->packet_count = 0;
                        meta->byte_count = 0;
                    }
                }
            }
            processed_count++;
        }

        // Throttle scavenger execution intervals to minimize memory bus contention
        rte_delay_us_sleep(GC_SLEEP_MS * 1000);
    }

    printf("[ALKIRA GC ENGINE] Scavenger thread unmounted gracefully.\n");
    return 0;
}

