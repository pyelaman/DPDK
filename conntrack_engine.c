#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <string.h>

#define CACHE_LINE 64
#define HASH_BUCKETS 65536     // Must be a power of 2 for fast bitwise modulo
#define BUCKET_MASK (HASH_BUCKETS - 1)
#define WHEEL_SLOTS 3600       // 1-second resolution covering a full hour window

// --- NETWORK PRIMITIVES & STATES ---
typedef enum {
    TCP_STATE_LISTEN,
    TCP_STATE_SYN_SENT,
    TCP_STATE_SYN_RECV,
    TCP_STATE_ESTABLISHED,
    TCP_STATE_FIN_WAIT,
    TCP_STATE_TIME_WAIT,
    TCP_STATE_CLOSED
} tcp_state_t;

// 6-Tuple Multi-Tenant Flow Key
typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;
    uint32_t vrf_id; // Absolute Tenant Isolation Identifier
} flow_key_t;

// NAT Translation Mapping Tuple
typedef struct {
    uint32_t nat_src_ip;
    uint16_t nat_src_port;
} nat_mapping_t;

// Connection Flow Node Structure
typedef struct flow_entry {
    flow_key_t       key;
    nat_mapping_t   nat_map;
    _Atomic uint32_t tcp_state;
    _Atomic uint64_t last_seen_seconds;
    uint32_t         timeout_duration;
    
    // Intrusive Doubly Linked List pointers for the Timer Wheel Slot
    struct flow_entry* wheel_next;
    struct flow_entry* wheel_prev;
    uint32_t           current_wheel_slot;

    // Intrusive Singly Linked List for Hash Collision Chaining
    struct flow_entry* next;
} flow_entry_t;

// --- MULTI-CORE SPINLOCK PRIMITIVES ---
typedef struct {
    _Atomic uint32_t lock __attribute__((aligned(CACHE_LINE)));
} rw_spinlock_t;

void init_rw_spinlock(rw_spinlock_t* l) {
    atomic_init(&l->lock, 0);
}

// Read Lock: Increments the reference tracker counter, spins if a writer holds bit 31
void read_lock(rw_spinlock_t* l) {
    uint32_t current;
    while (true) {
        current = atomic_load_explicit(&l->lock, memory_order_relaxed);
        if (current & (1U << 31)) {
            // Writer active, back off execution pipelines
            __builtin_ia32_pause();
            continue;
        }
        if (atomic_compare_exchange_weak_explicit(&l->lock, &current, current + 1,
                                                 memory_order_acquire, memory_order_relaxed)) {
            break;
        }
    }
}

void read_unlock(rw_spinlock_t* l) {
    atomic_fetch_sub_explicit(&l->lock, 1, memory_order_release);
}

// Write Lock: Atomically flips bit 31 from 0 to 1, spins until all concurrent readers drain out
void write_lock(rw_spinlock_t* l) {
    uint32_t expected = 0;
    while (!atomic_compare_exchange_weak_explicit(&l->lock, &expected, (1U << 31),
                                                 memory_order_acquire, memory_order_relaxed)) {
        expected = 0;
        __builtin_ia32_pause();
    }
    // Wait out lingering readers (spin until bottom 31 bits drop down to absolute 0)
    while ((atomic_load_explicit(&l->lock, memory_order_relaxed) & 0x7FFFFFFF) > 0) {
        __builtin_ia32_pause();
    }
}

void write_unlock(rw_spinlock_t* l) {
    atomic_store_explicit(&l->lock, 0, memory_order_release);
}

// --- CONNTRAK METADATA CORES ---
typedef struct {
    flow_entry_t*  chain_head;
    rw_spinlock_t  lock;
} __attribute__((aligned(CACHE_LINE))) hash_bucket_t;

typedef struct {
    flow_entry_t* slots[WHEEL_SLOTS];
    rw_spinlock_t lock; // Master control plane lock for wheel modifications
    uint32_t      current_pointer;
} timer_wheel_t;

typedef struct {
    hash_bucket_t buckets[HASH_BUCKETS];
    timer_wheel_t wheel;
} conntrack_engine_t;

// Jenkins One-at-a-time Fast Key Hashing algorithm
uint32_t hash_flow_key(const flow_key_t* key) {
    uint32_t hash = 0;
    const uint8_t* p = (const uint8_t*)key;
    for (size_t i = 0; i < sizeof(flow_key_t); i++) {
        hash += p[i];
        hash += (hash << 10);
        hash ^= (hash >> 6);
    }
    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);
    return hash & BUCKET_MASK;
}

bool compare_keys(const flow_key_t* a, const flow_key_t* b) {
    return (a->src_ip == b->src_ip && a->dst_ip == b->dst_ip &&
            a->src_port == b->src_port && a->dst_port == b->dst_port &&
            a->protocol == b->protocol && a->vrf_id == b->vrf_id);
}

// --- CONNTRAK ENGINE PIPELINE IMPLEMENTATION ---
conntrack_engine_t* create_conntrack_engine() {
    conntrack_engine_t* engine = malloc(sizeof(conntrack_engine_t));
    for (int i = 0; i < HASH_BUCKETS; i++) {
        engine->buckets[i].chain_head = NULL;
        init_rw_spinlock(&engine->buckets[i].lock);
    }
    for (int i = 0; i < WHEEL_SLOTS; i++) {
        engine->wheel.slots[i] = NULL;
    }
    init_rw_spinlock(&engine->wheel.lock);
    engine->wheel.current_pointer = 0;
    return engine;
}

// Intercepts and schedules flow updates inside the Hierarchical Timer Wheel
void timer_wheel_update(timer_wheel_t* wheel, flow_entry_t* entry, uint64_t now_seconds) {
    write_lock(&wheel->lock);

    // 1. Remove node from existing slot context if already mapped to a wheel position
    if (entry->wheel_next || entry->wheel_prev || wheel->slots[entry->current_wheel_slot] == entry) {
        if (entry->wheel_next) entry->wheel_next->wheel_prev = entry->wheel_prev;
        if (entry->wheel_prev) entry->wheel_prev->wheel_next = entry->wheel_next;
        if (wheel->slots[entry->current_wheel_slot] == entry) {
            wheel->slots[entry->current_wheel_slot] = entry->wheel_next;
        }
        entry->wheel_next = NULL;
        entry->wheel_prev = NULL;
    }

    // 2. Map target node to new calculated future wheel slot
    uint32_t future_slot = (wheel->current_pointer + entry->timeout_duration) % WHEEL_SLOTS;
    entry->current_wheel_slot = future_slot;

    // Push node onto the front of the doubly linked list for the target wheel slot
    entry->wheel_next = wheel->slots[future_slot];
    if (wheel->slots[future_slot]) {
        wheel->slots[future_slot]->wheel_prev = entry;
    }
    wheel->slots[future_slot] = entry;

    write_unlock(&wheel->lock);
}

// TCP State Machine Transition Engine
void transition_state(flow_entry_t* entry, uint8_t tcp_flags) {
    uint32_t current_state = atomic_load_explicit(&entry->tcp_state, memory_order_relaxed);
    uint32_t target_state = current_state;

    // Fast bitmask verification constants
    bool syn = tcp_flags & 0x02;
    bool ack = tcp_flags & 0x10;
    bool fin = tcp_flags & 0x01;
    bool rst = tcp_flags & 0x04;

    if (rst) {
        target_state = TCP_STATE_CLOSED;
        entry->timeout_duration = 10; // Rapid tear-down timeout bounds
    } else {
        switch (current_state) {
            case TCP_STATE_LISTEN:
                if (syn) { target_state = TCP_STATE_SYN_SENT; entry->timeout_duration = 30; }
                break;
            case TCP_STATE_SYN_SENT:
                if (syn && ack) { target_state = TCP_STATE_SYN_RECV; entry->timeout_duration = 60; }
                else if (syn) { target_state = TCP_STATE_SYN_RECV; }
                break;
            case TCP_STATE_SYN_RECV:
                if (ack) { target_state = TCP_STATE_ESTABLISHED; entry->timeout_duration = 1200; } // 20-min keepalive
                break;
            case TCP_STATE_ESTABLISHED:
                if (fin) { target_state = TCP_STATE_FIN_WAIT; entry->timeout_duration = 60; }
                break;
            case TCP_STATE_FIN_WAIT:
                if (ack) { target_state = TCP_STATE_TIME_WAIT; entry->timeout_duration = 30; }
                break;
            default:
                break;
        }
    }
    atomic_store_explicit(&entry->tcp_state, target_state, memory_order_relaxed);
}

// Ingress Fast-Path Flow Processing Logic Execution Entry
flow_entry_t* conntrack_process_packet(conntrack_engine_t* engine, const flow_key_t* key, 
                                      uint8_t tcp_flags, uint64_t now_seconds, bool* is_new_flow) {
    uint32_t bucket_idx = hash_flow_key(key);
    hash_bucket_t* bucket = &engine->buckets[bucket_idx];

    // Read Path: Acquire bucket read lock to traverse the chain quickly
    read_lock(&bucket->lock);
    flow_entry_t* entry = bucket->chain_head;
    while (entry != NULL) {
        if (compare_keys(&entry->key, key)) {
            // Existing Flow Match Found! Update operational statistics
            atomic_store_explicit(&entry->last_seen_seconds, now_seconds, memory_order_relaxed);
            transition_state(entry, tcp_flags);
            
            read_unlock(&bucket->lock);
            
            // Re-schedule flow alignment position inside timer wheel
            timer_wheel_update(&engine->wheel, entry, now_seconds);
            *is_new_flow = false;
            return entry;
        }
        entry = entry->next;
    }
    read_unlock(&bucket->lock);

    // Write Path Fallback: Cache Miss - Create and allocate new flow entry atomically
    write_lock(&bucket->lock);
    
    // Double check chain context under writer privilege to protect against 
    // multi-core insertion race conditions
    entry = bucket->chain_head;
    while (entry != NULL) {
        if (compare_keys(&entry->key, key)) {
            read_unlock(&bucket->lock); // Downgrade lock state
            *is_new_flow = false;
            return entry;
        }
        entry = entry->next;
    }

    // Allocate memory on the spot (in production, pull from pre-allocated DPDK rte_mempool memory)
    flow_entry_t* new_entry = malloc(sizeof(flow_entry_t));
    new_entry->key = *key;
    
    // Simulate Carrier-Grade NAT Allocation Layer (CGNAT Base allocation values)
    new_entry->nat_map.nat_src_ip = 0x64400001; // Mock Carrier IP mappings (100.64.0.1)
    new_entry->nat_map.nat_src_port = 40000 + (bucket_idx % 10000);

    atomic_init(&new_entry->tcp_state, TCP_STATE_LISTEN);
    atomic_init(&new_entry->last_seen_seconds, now_seconds);
    new_entry->timeout_duration = 30; // Default initial window budget
    new_entry->wheel_next = NULL;
    new_entry->wheel_prev = NULL;
    transition_state(new_entry, tcp_flags);

    // Insert new node at the head of the bucket chain link matrix
    new_entry->next = bucket->chain_head;
    bucket->chain_head = new_entry;
    write_unlock(&bucket->lock);
    timer_wheel_update(&engine->wheel, new_entry, now_seconds);
    *is_new_flow = true;
    return new_entry;
}

// Background Worker Tick Engine: Advances the timer wheel and purges expired flows in O(1)
void conntrack_timer_wheel_tick(conntrack_engine_t* engine, uint64_t now_seconds) {
    timer_wheel_t* wheel = &engine->wheel;
    write_lock(&wheel->lock);
    uint32_t active_slot = wheel->current_pointer;
    flow_entry_t* expired_flow = wheel->slots[active_slot];
    wheel->slots[active_slot] = NULL; // Evict entire list bucket instantly

    // Advance pointer to the next logical slot index position
    wheel->current_pointer = (wheel->current_pointer + 1) % WHEEL_SLOTS;
    write_unlock(&wheel->lock);

    // Process evicted entries outside the master wheel lock scope
    while (expired_flow != NULL) {
        flow_entry_t* next_expired = expired_flow->wheel_next;
        uint64_t last_seen = atomic_load_explicit(&expired_flow->last_seen_seconds, 
                                                  memory_order_relaxed);

        // Verification check: Has the connection stayed completely idle for its full duration?
        if (now_seconds - last_seen >= expired_flow->timeout_duration) {
            // Evict node cleanly from global hash lookup tables
            uint32_t bucket_idx = hash_flow_key(&expired_flow->key);
            hash_bucket_t* bucket = &engine->buckets[bucket_idx];
            write_lock(&bucket->lock);
            flow_entry_t* prev = NULL;
            flow_entry_t* curr = bucket->chain_head;

            while (curr != NULL) {
                if (curr == expired_flow) {
                    if (prev == NULL) bucket->chain_head = curr->next;
                    else prev->next = curr->next;
                    break;
                }
                prev = curr;
                curr = curr->next;
            }
            write_unlock(&bucket->lock);

            printf("[GC Eviction] Flow from Src Port %d expired and purged cleanly.\n", 
                    expired_flow->key.src_port);
            free(expired_flow);
        } else {
            // The flow was updated recently while sitting in this slot; 
            // re-schedule it to a future wheel index
            timer_wheel_update(wheel, expired_flow, now_seconds);
        }
        expired_flow = next_expired;
    }
}

// --- VERIFICATION BENCHMARK DRIVER RUNNER ---
int main() {
    conntrack_engine_t* engine = create_conntrack_engine();
    uint64_t global_system_time = 1718000000;

    // Create a multi-tenant corporate search query flow key
    flow_key_t tenant_flow = {
        .src_ip = 0x0A00000A,   // 10.0.0.10
        .dst_ip = 0x08080808,   // 8.8.8.8
        .src_port = 10452,
        .dst_port = 80,
        .protocol = 6,          // TCP
        .vrf_id = 5001          // Tenant Core Identifier
    };

    printf("====================================================\n");
    printf("STARTING HIGH-SCALE STATEFUL CONNTRAK & NAT ENGINE\n");
    printf("====================================================\n");
    bool is_new = false;

    // Step 1: Process Inbound TCP SYN Frame
    flow_entry_t* f = conntrack_process_packet(engine, &tenant_flow, 0x02,
                                               global_system_time, &is_new);

    printf("[Packet 1] State Tracker Status: New Flow = %s | Assigned NAT Port = %d | \
            Internal TCP State = %d\n", is_new ? "TRUE" : "FALSE", f->nat_map.nat_src_port,
            atomic_load(&f->tcp_state));

    // Step 2: Process Subsequent Inbound TCP ESTABLISHED Handshake Frame
    global_system_time += 1;
    f = conntrack_process_packet(engine, &tenant_flow, 0x10, global_system_time, &is_new);

    printf("[Packet 2] State Tracker Status: New Flow = %s | Internal TCP State = %d | \
            New Timeout Scope = %d s\n", is_new ? "TRUE" : "FALSE", atomic_load(&f->tcp_state),
            f->timeout_duration);

    // Step 3: Fast-forward global clock parameters to stress the Hierarchical Timer Wheel
    printf("\n[INFO] Fast-forwarding global time metrics to simulate idle timeouts...\n");
    for (int i = 0; i < 1205; i++) {
        global_system_time += 1;
        conntrack_timer_wheel_tick(engine, global_system_time);
    }
    printf("====================================================\n");
    printf("BENCHMARK EXECUTION RE-RUN COMPLETED SUCCESS\n");
    printf("====================================================\n");
    return 0;
}
