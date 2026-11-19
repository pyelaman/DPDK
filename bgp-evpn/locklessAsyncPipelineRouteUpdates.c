#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>
#include <unistd.h>
#include <stdbool.h>

#define RING_BUFFER_SIZE 64

typedef struct {
    uint32_t simulated_prefix;
    uint32_t simulated_metric;
} bgp_update_event_t;

// Lockless Single-Producer Single-Consumer (SPSC) Queue structure
typedef struct {
    bgp_update_event_t buffer[RING_BUFFER_SIZE];
    volatile uint32_t head;
    volatile uint32_t tail;
} spsc_ring_buffer_t;

spsc_ring_buffer_t shared_ring = { .head = 0, .tail = 0 };

// Enqueue operation performed exclusively by the Inbound Socket Reader thread
bool enqueue_update_event(bgp_update_event_t event) {
    uint32_t current_tail = shared_ring.tail;
    uint32_t next_tail = (current_tail + 1) % RING_BUFFER_SIZE;
    
    if (next_tail == shared_ring.head) {
        return false; // Queue is full. Drop or apply TCP backpressure.
    }
    
    shared_ring.buffer[current_tail] = event;
    __sync_synchronize(); // Memory barrier to guarantee execution ordering
    shared_ring.tail = next_tail;
    return true;
}

// Deenqueue operation performed exclusively by the Background Processing Thread
bool dequeue_update_event(bgp_update_event_t *out_event) {
    uint32_t current_head = shared_ring.head;
    
    if (current_head == shared_ring.tail) {
        return false; // Queue is empty. No pending traffic updates.
    }
    
    *out_event = shared_ring.buffer[current_head];
    __sync_synchronize(); // Memory barrier
    shared_ring.head = (current_head + 1) % RING_BUFFER_SIZE;
    return true;
}

// Thread 1: Inbound Socket Reader
void* socket_reader_thread_entry(void *arg) {
    (void)arg;
    for (uint32_t i = 0; i < 5; i++) {
        bgp_update_event_t incoming_packet = { .simulated_prefix = 0x10000000 + i, 
                                               .simulated_metric = 10 };

        while (!enqueue_update_event(incoming_packet)) {
            usleep(1000); // Retry loop if the ring buffer fills up
        }

        printf("[SOCKET THREAD] Ingested raw packet event for prefix update: 0x%X\n", 
                incoming_packet.simulated_prefix);
        usleep(10000); // Simulate standard socket inter-arrival delays
    }
    return NULL;
}

// Thread 2: Background BGP RIB Calculation Engine
void* rib_engine_thread_entry(void *arg) {
    (void)arg;
    uint32_t processed_count = 0;
    while (processed_count < 5) {
        bgp_update_event_t task;
        if (dequeue_update_event(&task)) {
            printf("  --> [RIB PROCESSING THREAD] Executed complex best-path logic for route: 0x%X\n",
                   task.simulated_prefix);
            processed_count++;
        } else {
            usleep(5000); // Idle backoff if the queue is temporarily empty
        }
    }
    return NULL;
}

int main(void) {
    pthread_t reader_id, engine_id;
    printf("--- Initializing Multi-threaded Asynchronous Control Pipeline ---\n");

    pthread_create(&reader_id, NULL, socket_reader_thread_entry, NULL);
    pthread_create(&engine_id, NULL, rib_engine_thread_entry, NULL);

    pthread_join(reader_id, NULL);
    pthread_join(engine_id, NULL);

    printf("[SUCCESS] Asynchronous thread execution completed cleanly.\n");
    return 0;
}

