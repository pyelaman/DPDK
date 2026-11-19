#define _GNU_SOURCE

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <pthread.h>
#include <unistd.h>
#include <sched.h>

/*

   1. memory_order_relaxed (Read or Write. No re-ordering constraints enforced)

	• The Rule: Guarantees that the operation itself is atomic, 
	            but imposes zero ordering constraints on any surrounding memory operations.

	• CPU Behavior: The compiler and CPU are completely free to reorder any independent reads or writes 
	                before or after this atomic operation.

	• When to Use: Use this for counters or metrics where accuracy matters, 
	               but where other data elements do not depend on its sequencing.

	• Real-World Example: Incrementing packet or byte counters inside an Alkira fast-path loop, 
	                      or reading a loop shutdown flag.

   2. memory_order_release (Write only. Prior writes cannot sink below this line) 

	• The Rule: Applied to write (store) operations. It guarantees that all preceding memory writes 
	            (both atomic and non-atomic) are completely flushed to cache/memory and visible 
		    before this specific atomic write commits.

	• CPU Behavior: Prevents any prior memory operations from being reordered after this store. 
	                It acts as a one-way gate pushing data down the pipeline.

	• When to Use: Use this when a thread has finished preparing a packet payload or descriptor 
	               and needs to hand it off safely to another core.

	• Real-World Example: Advancing the head or tail pointer of a ring buffer after writing a payload array.

   3. memory_order_acquire (Read only. Subsequent reads/writes cannot float above this line)

	• The Rule: Applied to read (load) operations. It guarantees that all subsequent memory operations 
	            (reads or writes) cannot be executed until after this atomic read successfully completes.

	• CPU Behavior: Prevents downstream instructions from bleeding backward or being speculatively 
	                executed before this barrier.

	• When to Use: Use this when a thread reads a control variable indicating that a remote thread 
	               has handed off a new job or payload chunk.

	• Real-World Example: Reading a ring buffer index to safely consume a packet



Variable Pointer	Purpose in the MPMC Architecture	Synchronization Role
================        ================================        ====================
prod.head	        Tracks slot reservations for producers	CAS loops to resolve multi-core races.
prod.tail	        Tracks fully committed producer slots	Spin-waiting to ensure consecutive, hole-free data order.
cons.head	        Tracks slot reservations for consumers	CAS loops to prevent m-consumers from reading same packet.
cons.tail	        Tracks fully read slots for safe reuse	Spin-waiting to release chunks back to producers in order.

*/

/* Compatibility definitions to run standalone without full DPDK dependencies */
#define __rte_cache_aligned __attribute__((__aligned__(64)))
#define RTE_CACHE_LINE_SIZE 64
#define unlikely(x)         __builtin_expect(!!(x), 0)
#define likely(x)           __builtin_expect(!!(x), 1)
#define rte_pause()         __asm__ __volatile__("pause" ::: "memory")

// --- SPSC RING BUFFER FROM PREVIOUS STEP ---
#define SPSC_CAPACITY 4096
#define SPSC_MASK     (SPSC_CAPACITY - 1)

struct lockless_spsc_ring {
    _Atomic uint64_t head __rte_cache_aligned;
    _Atomic uint64_t tail __rte_cache_aligned;
    void *storage[SPSC_CAPACITY] __rte_cache_aligned;
};

struct lockless_spsc_ring* lockless_spsc_create(void) {
    struct lockless_spsc_ring *ring = NULL;
    if (posix_memalign((void **)&ring, RTE_CACHE_LINE_SIZE, sizeof(struct lockless_spsc_ring)) != 0) return NULL;
    atomic_init(&ring->head, 0);
    atomic_init(&ring->tail, 0);
    return ring;
}

inline int lockless_spsc_enqueue(struct lockless_spsc_ring *ring, void *obj) {
    uint64_t current_head = atomic_load_explicit(&ring->head, memory_order_relaxed);
    uint64_t current_tail = atomic_load_explicit(&ring->tail, memory_order_acquire);
    if (unlikely((current_head - current_tail) >= SPSC_CAPACITY)) return -1;
    ring->storage[current_head & SPSC_MASK] = obj;
    atomic_store_explicit(&ring->head, current_head + 1, memory_order_release);
    return 0;
}

inline void* lockless_spsc_dequeue(struct lockless_spsc_ring *ring) {
    uint64_t current_tail = atomic_load_explicit(&ring->tail, memory_order_relaxed);
    uint64_t current_head = atomic_load_explicit(&ring->head, memory_order_acquire);
    if (unlikely(current_tail == current_head)) return NULL;
    void *obj = ring->storage[current_tail & SPSC_MASK];
    atomic_store_explicit(&ring->tail, current_tail + 1, memory_order_release);
    return obj;
}


// --- MPMC RING BUFFER FROM PREVIOUS STEP ---
#define MPMC_CAPACITY 4096
#define MPMC_MASK     (MPMC_CAPACITY - 1)

struct lockless_mpmc_ring {
    struct { _Atomic uint64_t head; _Atomic uint64_t tail; } prod __rte_cache_aligned;
    struct { _Atomic uint64_t head; _Atomic uint64_t tail; } cons __rte_cache_aligned;
    void *_Atomic storage[MPMC_CAPACITY] __rte_cache_aligned;
};

struct lockless_mpmc_ring* lockless_mpmc_create(void) {
    struct lockless_mpmc_ring *ring = NULL;
    if (posix_memalign((void **)&ring, RTE_CACHE_LINE_SIZE, sizeof(struct lockless_mpmc_ring)) != 0) return NULL;
    atomic_init(&ring->prod.head, 0); atomic_init(&ring->prod.tail, 0);
    atomic_init(&ring->cons.head, 0); atomic_init(&ring->cons.tail, 0);
    for (int i = 0; i < MPMC_CAPACITY; i++) atomic_init(&ring->storage[i], NULL);
    return ring;
}

uint32_t mpmc_enqueue_burst(struct lockless_mpmc_ring *ring, void **obj_table, uint32_t n) {
    uint64_t prod_head, cons_tail, next_prod_head;
    uint32_t free_entries;
    bool success;
    do {
        prod_head = atomic_load_explicit(&ring->prod.head, memory_order_relaxed);
        cons_tail = atomic_load_explicit(&ring->cons.tail, memory_order_acquire);
        free_entries = (MPMC_CAPACITY - (prod_head - cons_tail));
        if (unlikely(n > free_entries)) { n = free_entries; if (unlikely(n == 0)) return 0; }
        next_prod_head = prod_head + n;
        success = atomic_compare_exchange_weak_explicit(&ring->prod.head, &prod_head, next_prod_head, memory_order_relaxed, memory_order_relaxed);
    } while (unlikely(!success));

    for (uint32_t i = 0; i < n; i++) {
        atomic_store_explicit(&ring->storage[(prod_head + i) & MPMC_MASK], obj_table[i], memory_order_relaxed);
    }
    while (unlikely(atomic_load_explicit(&ring->prod.tail, memory_order_relaxed) != prod_head)) rte_pause();
    atomic_store_explicit(&ring->prod.tail, next_prod_head, memory_order_release);
    return n;
}

uint32_t mpmc_dequeue_burst(struct lockless_mpmc_ring *ring, void **obj_table, uint32_t n) {
    uint64_t cons_head, prod_tail, next_cons_head;
    uint32_t available_entries;
    bool success;
    do {
        cons_head = atomic_load_explicit(&ring->cons.head, memory_order_relaxed);
        prod_tail = atomic_load_explicit(&ring->prod.tail, memory_order_acquire);
        available_entries = (prod_tail - cons_head);
        if (unlikely(n > available_entries)) { n = available_entries; if (unlikely(n == 0)) return 0; }
        next_cons_head = cons_head + n;
        success = atomic_compare_exchange_weak_explicit(&ring->cons.head, &cons_head, next_cons_head, memory_order_relaxed, memory_order_relaxed);
    } while (unlikely(!success));

    for (uint32_t i = 0; i < n; i++) {
        obj_table[i] = atomic_load_explicit(&ring->storage[(cons_head + i) & MPMC_MASK], memory_order_relaxed);
    }
    while (unlikely(atomic_load_explicit(&ring->cons.tail, memory_order_relaxed) != cons_head)) rte_pause();
    atomic_store_explicit(&ring->cons.tail, next_cons_head, memory_order_release);
    return n;
}


// --- MAIN DRIVER AND THREAD ORCHESTRATION ---

/* Mock packet descriptor mimicking an Alkira multi-cloud packet payload metadata context */
typedef struct {
    uint32_t packet_id;
    uint32_t vni_tag;
    uint16_t latency_marker;
} cnaas_packet_t;

/* Thread parameter block handles pinning definitions and structure pass links */
typedef struct {
    int core_id;
    void *ring_ptr;
    _Atomic bool *shutdown_flag;
} thread_ctx_t;

// Utility to set thread affinity outside DPDK EAL environments
void cpu_set_setcpuid(int core_id) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
}

// SPSC Producer Execution Loop
void* spsc_producer_thread(void *arg) {
    thread_ctx_t *ctx = (thread_ctx_t *)arg;
    struct lockless_spsc_ring *ring = (struct lockless_spsc_ring *)ctx->ring_ptr;
    
    cpu_set_setcpuid(ctx->core_id); // Pin thread context to designated core allocation layout
    printf("[SPSC_PRODUCER] Thread deployed and pinned on Core %d\n", ctx->core_id);

    uint32_t seq = 0;
    while (!atomic_load(ctx->shutdown_flag)) {
        cnaas_packet_t *pkt = malloc(sizeof(cnaas_packet_t));
        pkt->packet_id = ++seq;
        pkt->vni_tag = 20050;

        // Attempt enqueue backpressure loop spin
        while (lockless_spsc_enqueue(ring, pkt) != 0 && !atomic_load(ctx->shutdown_flag)) {
            rte_pause(); // Backpressure wait state
        }
    }
    return NULL;
}

// SPSC Consumer Execution Loop
void* spsc_consumer_thread(void *arg) {
    thread_ctx_t *ctx = (thread_ctx_t *)arg;
    struct lockless_spsc_ring *ring = (struct lockless_spsc_ring *)ctx->ring_ptr;
    
    cpu_set_setcpuid(ctx->core_id);
    printf("[SPSC_CONSUMER] Thread deployed and pinned on Core %d\n", ctx->core_id);

    uint64_t consumed_count = 0;
    while (!atomic_load(ctx->shutdown_flag) || lockless_spsc_dequeue(ring) != NULL) {
        cnaas_packet_t *pkt = lockless_spsc_dequeue(ring);
        if (pkt != NULL) {
            consumed_count++;
            if (unlikely(pkt->packet_id % 500000 == 0)) {
                printf("[SPSC_CONSUMER] Handled packet marker ID: %u across isolated core bus\n", pkt->packet_id);
            }
            free(pkt); // Free metadata allocation
        } else {
            rte_pause(); // Idle queue pause optimization
        }
    }
    printf("[SPSC_CONSUMER] Total isolated sessions handoff pipeline count: %lu\n", consumed_count);
    return NULL;
}

// MPMC Producer Burst Execution Loop
void* mpmc_producer_thread(void *arg) {
    thread_ctx_t *ctx = (thread_ctx_t *)arg;
    struct lockless_mpmc_ring *ring = (struct lockless_mpmc_ring *)ctx->ring_ptr;
    
    cpu_set_setcpuid(ctx->core_id);
    printf("[MPMC_PRODUCER_C%d] Active on multi-producer core ring loop\n", ctx->core_id);

    uint32_t seq = 0;
    void *burst_table[128]; // Allocate small burst table caches local to thread footprint
    
    while (!atomic_load(ctx->shutdown_flag)) {
        for (int i = 0; i < 128; i++) {
            cnaas_packet_t *pkt = malloc(sizeof(cnaas_packet_t));
            pkt->packet_id = ++seq;
            burst_table[i] = pkt;
        }

        uint32_t enqueued = 0;
        while (enqueued < 128 && !atomic_load(ctx->shutdown_flag)) {
            enqueued += mpmc_enqueue_burst(ring, &burst_table[enqueued], 128 - enqueued);
            if (enqueued < 128) rte_pause();
        }
    }
    return NULL;
}

// MPMC Consumer Burst Execution Loop
void* mpmc_consumer_thread(void *arg) {
    thread_ctx_t *ctx = (thread_ctx_t *)arg;
    struct lockless_mpmc_ring *ring = (struct lockless_mpmc_ring *)ctx->ring_ptr;
    
    cpu_set_setcpuid(ctx->core_id);
    printf("[MPMC_CONSUMER_C%d] Active on multi-consumer core ring loop\n", ctx->core_id);

    uint64_t total_dequeued = 0;
    void *burst_table[128];

    while (!atomic_load(ctx->shutdown_flag)) {
        uint32_t dequeued = mpmc_dequeue_burst(ring, burst_table, 128);
        if (dequeued > 0) {
            total_dequeued += dequeued;
            for (uint32_t i = 0; i < dequeued; i++) {
                free(burst_table[i]);
            }
        } else {
            rte_pause();
        }
    }
    printf("[MPMC_CONSUMER_C%d] Clean exit. Processed total of %lu packets.\n", ctx->core_id, total_dequeued);
    return NULL;
}

int main(int argc, char **argv) {
    printf("--- STARTING PRINCIPAL DATA-PLANE PRIMITIVE DRIVER TEST ---\n");
    _Atomic bool global_shutdown = false;

    /* 1. TEST WORKSPACE PIPELINE: SINGLE PRODUCER SINGLE CONSUMER */
    printf("\n[STAGE 1] Testing SPSC Lockless Inter-Core Processing Fabric\n");
    struct lockless_spsc_ring *spsc_ring = lockless_spsc_create();
    
    thread_ctx_t spsc_prod_ctx = { .core_id = 1, .ring_ptr = spsc_ring, .shutdown_flag = &global_shutdown };
    thread_ctx_t spsc_cons_ctx = { .core_id = 2, .ring_ptr = spsc_ring, .shutdown_flag = &global_shutdown };

    pthread_t t1, t2;
    pthread_create(&t1, NULL, spsc_producer_thread, &spsc_prod_ctx);
    pthread_create(&t2, NULL, spsc_consumer_thread, &spsc_cons_ctx);
    sleep(3); // Let the execution loops crunch packets across cores 1 and 2

    atomic_store(&global_shutdown, true);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    /* 2. TEST WORKSPACE PIPELINE: MULTI-PRODUCER MULTI-CONSUMER */
    printf("\n[STAGE 2] Testing MPMC Multi-Thread Concurrent Collision Bus\n");
    atomic_store(&global_shutdown, false); // Reset control barrier flag
    struct lockless_mpmc_ring *mpmc_ring = lockless_mpmc_create();

    // Spawn 10 concurrent producers and 10 concurrent consumers running completely out-of-sync
    pthread_t p_threads[10], c_threads[10];
    thread_ctx_t p_ctx[10], c_ctx[10];

    for (int i = 0; i < 10; i++) {
        p_ctx[i] = (thread_ctx_t){ .core_id = 3 + i, .ring_ptr = mpmc_ring, .shutdown_flag = &global_shutdown };
        c_ctx[i] = (thread_ctx_t){ .core_id = 5 + i, .ring_ptr = mpmc_ring, .shutdown_flag = &global_shutdown };
        pthread_create(&p_threads[i], NULL, mpmc_producer_thread, &p_ctx[i]);
        pthread_create(&c_threads[i], NULL, mpmc_consumer_thread, &c_ctx[i]);
    }

    sleep(3); // Run concurrent processing across cores 3, 4, 5, and 6
    atomic_store(&global_shutdown, true);

    for (int i = 0; i < 10; i++) {
        pthread_join(p_threads[i], NULL);
        pthread_join(c_threads[i], NULL);
    }
    printf("\n--- ALL DATA PLANE SIMULATION TRACKS COMPLETE SUCCESSFULLY ---\n");
    return 0;
}
