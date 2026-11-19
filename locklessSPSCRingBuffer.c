#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <rte_common.h>
#include <rte_prefetch.h>
#include <rte_branch_prediction.h>

/* 
 * Ring capacity must be a power of two to optimize modulo index wrap-around 
 * operations down to a fast bitwise AND calculation.
 */
#define RING_CAPACITY 4096
#define RING_MASK     (RING_CAPACITY - 1)

/* 
 * 1. __rte_cache_aligned Macro: Forces the compiler to pad and isolate head, tail, and storage 
 *    into unique 64-byte structural memory footprints. This entirely bypasses inter-core L1/L2 hardware 
 *    thrashing cache invalidations.
 *
 * 2. memory_order_release: Prevents the compiler and CPU instruction pipeline from reordering memory operations. 
 *    This guarantees the packet data pointer is written to storage[index] before the remote consumer core 
 *    sees the incremented head index value.
 *
 * 3. memory_order_acquire: Ensures that when the producer evaluates current_tail 
 *    (or the consumer evaluates current_head), it reads the freshest atomic update synced 
 *    across the internal inter-core system interconnect bus.
 *
 * 4. Power-of-Two Bitwise Optimization: Utilizing current_head & RING_MASK instead of an expensive 
 *    modulo arithmetic division operation (%) allows the CPU compiler to generate standard single-cycle 
 *    assembly bitwise operations (AND). This optimization saves critical clock cycles during line-rate 
 *    packet processing loops.
*/

struct lockless_spsc_ring {
    /* Cache line 1: Shared metadata and Producer tracking states */
    _Atomic uint64_t head __rte_cache_aligned;
    
    /* Cache line 2: Consumer tracking states isolated to prevent false sharing */
    _Atomic uint64_t tail __rte_cache_aligned;

    /* Cache line 3: The actual underlying pointer block ring array */
    void *storage[RING_CAPACITY] __rte_cache_aligned;
};

/*
 * Instantiate and initialize a cache-aligned lockless ring structure
 */
struct lockless_spsc_ring* lockless_ring_create(void) {
    struct lockless_spsc_ring *ring = NULL;
    
    // Allocate contiguous memory aligned explicitly to CPU cache boundaries
    int ret = posix_memalign((void **)&ring, RTE_CACHE_LINE_SIZE, sizeof(struct lockless_spsc_ring));
    if (unlikely(ret != 0 || ring == NULL)) {
        return NULL;
    }

    atomic_init(&ring->head, 0);
    atomic_init(&ring->tail, 0);
    
    for (int i = 0; i < RING_CAPACITY; i++) {
        ring->storage[i] = NULL;
    }

    return ring;
}

/*
 * Producer Core Function: Enqueue an object onto the ring
 * Returns 0 on success, or -1 if the ring buffer is completely full.
 */
int inline lockless_ring_enqueue(struct lockless_spsc_ring *ring, void *obj) {
    // Acquire the current pointers using relaxed memory ordering loops
    uint64_t current_head = atomic_load_explicit(&ring->head, memory_order_relaxed);
    uint64_t current_tail = atomic_load_explicit(&ring->tail, memory_order_acquire);

    // Check if space remains available in the ring container
    if (unlikely((current_head - current_tail) >= RING_CAPACITY)) {
        return -1; // Ring buffer full condition
    }

    // Insert the pointer into the array mapping index without masking loop branch blocks
    uint32_t index = (uint32_t)(current_head & RING_MASK);
    ring->storage[index] = obj;

    /*
     * Release Memory Barrier: Guarantees that the object write above completes 
     * in the CPU pipeline before the updated head index becomes visible to the consumer.
     */
    atomic_store_explicit(&ring->head, current_head + 1, memory_order_release);
    return 0;
}

/*
 * Consumer Core Function: Dequeue an object from the ring
 * Returns the object pointer on success, or NULL if the ring buffer is empty.
 */
inline void* lockless_ring_dequeue(struct lockless_spsc_ring *ring) {
    uint64_t current_tail = atomic_load_explicit(&ring->tail, memory_order_relaxed);
    uint64_t current_head = atomic_load_explicit(&ring->head, memory_order_acquire);

    // Check if there are items available to consume
    if (unlikely(current_tail == current_head)) {
        return NULL; // Ring buffer empty condition
    }

    uint32_t index = (uint32_t)(current_tail & RING_MASK);
    void *obj = ring->storage[index];

    // Optional: Prefetch the referenced payload structure early into L1 Cache
    rte_prefetch0(obj);

    /*
     * Release Memory Barrier: Guarantees that the object is fully read 
     * before updating the tail pointer, preventing the producer from overwriting this slot.
     */
    atomic_store_explicit(&ring->tail, current_tail + 1, memory_order_release);
    return obj;
}

/*
 * Utility diagnostic counters to monitor queue pressure levels
 */
uint32_t inline lockless_ring_depth(struct lockless_spsc_ring *ring) {
    uint64_t current_head = atomic_load_explicit(&ring->head, memory_order_relaxed);
    uint64_t current_tail = atomic_load_explicit(&ring->tail, memory_order_relaxed);
    return (uint32_t)(current_head - current_tail);
}

int main() {
   return 0;
}
