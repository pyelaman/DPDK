#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <rte_ether.h>
#include <rte_ip.h>

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32
#define RING_SIZE 2048

/*
 * Core 1 never waits for hardware. It is a pure software engine. 
 * It aggressively grabs free memory slots out of the rte_mempool, 
 * formats them to look like network traffic, and hammers them into the rte_ring as fast as possible.
 *
 * Packet Source: Internal software: Artificially generated directly from the memory pool 
 *                                   using rte_pktmbuf_alloc_bulk
 * Mempool interaction: Active:      The application manually requests new buffer chunks (alloc) and 
 *                                   populates them with dummy MAC/IP headers.
 * Bottleneck: CPU/Memory Bound:     The speed is strictly limited by CPU execution limits and RAM bus bandwidth.
 * Real-world use-case: Benchmark Testing: Used to test pure software processing logic and memory throughput 
 *                                         without hardware dependencies.
 */

struct rte_mempool *mbuf_pool = NULL;
struct rte_ring *packet_ring = NULL;
volatile uint8_t force_quit = 0;

static void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\nStopping simulation cleanly...\n");
        force_quit = 1;
    }
}

/* ================== CORE 1: TRAFFIC GENERATOR (PRODUCER) ================== */
static int lcore_generator(void *arg) {
    unsigned int lcore_id = rte_lcore_id();
    uint64_t pkts_generated = 0;
    printf("Core %u: Traffic Generator started.\n", lcore_id);

    while (!force_quit) {
        struct rte_mbuf *bufs[BURST_SIZE];
        int i;

        /* 1. Allocate a batch of empty buffers from our Hugepage memory pool */
        if (rte_pktmbuf_alloc_bulk(mbuf_pool, bufs, BURST_SIZE) < 0) {
            continue; // Pool temporarily empty, retry
        }

        /* 2. Simulate network traffic by writing dummy packet headers */
        for (i = 0; i < BURST_SIZE; i++) {
            struct rte_mbuf *m = bufs[i];
            
            // Set packet data length (e.g., standard 64-byte ping packet)
            m->data_len = 64;
            m->pkt_len = 64;

            // Pre-fill a dummy Layer 2 Ethernet header
            struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
            memset(&eth->dst_addr, 0xAA, sizeof(struct rte_ether_addr)); // Dummy Destination MAC
            memset(&eth->src_addr, 0xBB, sizeof(struct rte_ether_addr)); // Dummy Source MAC
            eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
        }

        /* 3. Push the simulated packet pointers into the lockless ring */
        uint16_t enqueued = rte_ring_enqueue_burst(packet_ring, (void **)bufs, BURST_SIZE, NULL);
        pkts_generated += enqueued;

        /* Drop/Free packets if the ring overflows to avoid memory leaks */
        if (unlikely(enqueued < BURST_SIZE)) {
            for (i = enqueued; i < BURST_SIZE; i++) {
                rte_pktmbuf_free(bufs[i]);
            }
        }
        
        // Add a micro-delay so your terminal text doesn't scroll at millions of packets/sec
        rte_delay_us_block(500000); 
        printf("Core %u (Generator): Generated & Enqueued %u packets (Total: %lu)\n", 
               lcore_id, enqueued, pkts_generated);
    }
    return 0;
}

/* ================== CORE 2: PACKET PROCESSOR (CONSUMER) ================== */
static int lcore_processor(void *arg) {
    unsigned int lcore_id = rte_lcore_id();
    uint64_t pkts_processed = 0;
    printf("Core %u: Packet Processor started.\n", lcore_id);

    while (!force_quit) {
        struct rte_mbuf *bufs[BURST_SIZE];
        int i;

        /* 1. Pull packet pointers off the lockless communication ring */
        uint16_t dequeued = rte_ring_dequeue_burst(packet_ring, (void **)bufs, BURST_SIZE, NULL);
        if (dequeued == 0) {
            continue; // Ring is empty, poll again
        }

        pkts_processed += dequeued;

        /* 2. Process the packet metadata (Simulating a real data path action) */
        for (i = 0; i < dequeued; i++) {
            struct rte_mbuf *m = bufs[i];
            struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
            
            // Read or validate data inside the packet payload
            if (rte_be_to_cpu_16(eth->ether_type) == RTE_ETHER_TYPE_IPV4) {
                // In a real router app, you would parse the IP header here
            }

            /* 3. CRITICAL: Recycle the buffer back to the mempool */
            rte_pktmbuf_free(m);
        }

        printf("Core %u (Processor): Dequeued & Processed %u packets (Total: %lu)\n", 
               lcore_id, dequeued, pkts_processed);
    }
    return 0;
}

int main(int argc, char *argv[]) {
    signal(SIGINT, signal_handler);

    // Initialize EAL env (Bypasses NICs since we are simulating internally)
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_exit(EXIT_FAILURE, "EAL init failed\n");

    if (rte_lcore_count() < 2) {
        rte_exit(EXIT_FAILURE, "This simulation requires at least 2 cores (-l 1,2)\n");
    }

    // Initialize Mempool for holding our fake packets
    mbuf_pool = rte_pktmbuf_pool_create("SIM_MPOOL", NUM_MBUFS, MBUF_CACHE_SIZE, 0, 
                                        RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!mbuf_pool) rte_exit(EXIT_FAILURE, "Mempool creation failed\n");

    // Create the lockless ring buffer
    packet_ring = rte_ring_create("SIM_RING", RING_SIZE, rte_socket_id(), 
                                  RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (!packet_ring) rte_exit(EXIT_FAILURE, "Ring creation failed\n");

    // Identify assigned execution cores
    unsigned int main_core = rte_get_main_lcore();
    unsigned int worker_core = rte_get_next_lcore(main_core, 0, 0);

    /* Launch Processor (Consumer) on Worker Core */
    rte_eal_remote_launch(lcore_processor, NULL, worker_core);

    /* Run Generator (Producer) on the Main Core */
    lcore_generator(NULL);

    // Synchronize thread shutdown on exit
    rte_eal_mp_wait_lcore();

    rte_ring_free(packet_ring);
    printf("Simulation closed cleanly.\n");
    return 0;
}

