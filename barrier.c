#define _GNU_SOURCE  /* Expose Linux feature test macros for affinity */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <sched.h>

#define NUM_WORKERS 3

// Global native pthread barrier reference descriptor
pthread_barrier_t global_execution_barrier;

// Thread parameters context footprint
typedef struct {
    int core_id;
    int worker_id;
} thread_ctx_t;

/* 
 * Standalone Thread Affinity Helper (Re-verified definition)
 */
void pin_thread_to_core(int core_id) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
}

/*
 * Pthread Worker Execution Loop
 */
void* pipeline_worker_thread(void *arg) {
    thread_ctx_t *ctx = (thread_ctx_t *)arg;
    
    // Explicitly pin thread execution to an isolated core profile
    pin_thread_to_core(ctx->core_id);
    printf("[WORKER_%d] Deployed on Core %d. Executing Phase 1 calculation loops...\n", 
           ctx->worker_id, ctx->core_id);

    // Simulate asynchronous parsing/computational delay variations across cores
    usleep((rand() % 3 + 1) * 500000); 
    printf("[WORKER_%d] Finished Phase 1. Arriving at the barrier checkpoint.\n", ctx->worker_id);

    /*
     * NATIVE POSIX MEMORY AND EXECUTION BARRIER APIS
     * Under the hood, this function triggers an architectural compiler fence,
     * memory ordering constraints, and increments a thread rendezvous state counter.
     */
    int barrier_status = pthread_barrier_wait(&global_execution_barrier);

    /*
     * Exactly one thread in the synchronization cohort receives the return flag 
     * PTHREAD_BARRIER_SERIAL_THREAD. All other waiting threads receive 0.
     */
    if (barrier_status == PTHREAD_BARRIER_SERIAL_THREAD) {
        printf("\n[BARRIER MASTER] All threads successfully checked in. Tripping gate globally.\n\n");
    }

    // All threads cross this line at the same time, with full memory synchronization guaranteed
    printf("[WORKER_%d] Resuming Phase 2 in strict lockstep synchronizations.\n", ctx->worker_id);
    
    return NULL;
}

int main(int argc, char **argv) {
    srand(time(NULL));
    printf("--- TESTING NATIVE POSIX THREAD CONCURRENCY BARRIERS ---\n");

    pthread_t threads[NUM_WORKERS];
    thread_ctx_t contexts[NUM_WORKERS];

    /*
     * Initialize the native barrier framework.
     * Argument 1: Pointer to our barrier structure context.
     * Argument 2: Attribute modifiers (NULL for default layouts).
     * Argument 3: Count threshold (Number of threads that MUST check in before release).
     */
    if (pthread_barrier_init(&global_execution_barrier, NULL, NUM_WORKERS) != 0) {
        perror("Failed to instantiate the target pthread barrier");
        return EXIT_FAILURE;
    }

    // Spawn our thread array blocks
    for (int i = 0; i < NUM_WORKERS; i++) {
        contexts[i].worker_id = i + 1;
        contexts[i].core_id = i + 1; // Map sequentially across distinct CPU cores
        
        pthread_create(&threads[i], NULL, pipeline_worker_thread, &contexts[i]);
    }

    // Await structural join terminations
    for (int i = 0; i < NUM_WORKERS; i++) {
        pthread_join(threads[i], NULL);
    }

    // Clean up allocated barrier memory resources cleanly
    pthread_barrier_destroy(&global_execution_barrier);

    printf("\n--- ALL BARRIER PROCESSING COMPLETED CLEANLY ---\n");
    return EXIT_SUCCESS;
}

