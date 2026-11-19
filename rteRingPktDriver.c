#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <signal.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ring.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32
#define RING_SIZE 2048

/*
 *
 * Core 1 waits for hardware. 
 * If a physical device or a virtual switch doesn't push data into the NIC's ring buffer, 
 * rte_eth_rx_burst returns 0, and Core 1 spends its CPU cycles continuously idling/polling the hardware ring.
 *
 *  Packet source: External Hardware: Read from the virtual network card wire using rte_eth_rx_burst.
 *  Mempool interaction: Passive: The hardware driver manages buffer slicing. 
 *                       The app only recycles packets at the very end via rte_pktmbuf_free.
 *  Bottleneck: I/O Bound: The speed is constrained by how fast packets arrive at the VirtIO virtual interface.
 *  Real-World usecase: Production Routing: Used to move real data between live network nodes.
*/

struct rte_mempool *mbuf_pool = NULL;
struct rte_ring *packet_ring = NULL;
volatile uint8_t force_quit = 0;

static struct rte_eth_conf port_conf_default = {
    .rxmode = { .max_lro_pkt_size = RTE_ETHER_MAX_LEN },
};

static void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\n\nSignal %d received, preparing to exit cleanly...\n", signum);
        force_quit = 1;
    }
}

/* Port initialization stays the same as before */
static inline int port_init(uint16_t port, struct rte_mempool *mbuf_pool) {
    struct rte_eth_conf port_conf = port_conf_default;
    const uint16_t rx_rings = 1, tx_rings = 1;
    int retval;
    uint16_t q;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf txconf;

    if (!rte_eth_dev_is_valid_port(port)) return -1;
    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0) return retval;

    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval < 0) return retval;

    for (q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE, rte_eth_dev_socket_id(port), NULL, mbuf_pool);
        if (retval < 0) return retval;
    }

    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;
    for (q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE, rte_eth_dev_socket_id(port), &txconf);
        if (retval < 0) return retval;
    }

    retval = rte_eth_dev_start(port);
    if (retval < 0) return retval;

    rte_eth_promiscuous_enable(port);
    return 0;
}

/* ================== THREAD 1: RX PRODUCER ================== */
static int lcore_rx(void *arg) {
    uint16_t port = 0; // Read strictly from Port 0
    printf("Core %u started as RX Producer for Port %u\n", rte_lcore_id(), port);

    while (!force_quit) {
        struct rte_mbuf *bufs[BURST_SIZE];
        
        // 1. Fetch packets from hardware into our mempool buffers
        const uint16_t nb_rx = rte_eth_rx_burst(port, 0, bufs, BURST_SIZE);
        if (unlikely(nb_rx == 0)) continue;

        // 2. Locklessly queue the pointers into our ring topology
        uint16_t sent = rte_ring_enqueue_burst(packet_ring, (void *)bufs, nb_rx, NULL);
        
        // If ring overflows, free packet buffers back to mempool immediately to prevent leak
        if (unlikely(sent < nb_rx)) {
            uint16_t i;
            for (i = sent; i < nb_rx; i++) {
                rte_pktmbuf_free(bufs[i]);
            }
        }
    }
    return 0;
}

/* ================== THREAD 2: WORKER / TX CONSUMER ================== */
static int lcore_tx(void *arg) {
    uint16_t dst_port = 1; // Send strictly out Port 1
    printf("Core %u started as Worker/TX Consumer for Port %u\n", rte_lcore_id(), dst_port);

    while (!force_quit) {
        struct rte_mbuf *bufs[BURST_SIZE];

        // 1. Fetch packet references out of our shared software ring
        const uint16_t nb_rx = rte_ring_dequeue_burst(packet_ring, (void **)bufs, BURST_SIZE, NULL);
        if (unlikely(nb_rx == 0)) continue;

        // 2. Simple L2 Processing Hook (e.g., Modify MAC header if needed)
        // struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(bufs[0], struct rte_ether_hdr *);

        // 3. Emit packets directly to destination hardware interface queues
        const uint16_t nb_tx = rte_eth_tx_burst(dst_port, 0, bufs, nb_rx);

        // Free anything that failed transmission
        if (unlikely(nb_tx < nb_rx)) {
            uint16_t i;
            for (i = nb_tx; i < nb_rx; i++) {
                rte_pktmbuf_free(bufs[i]);
            }
        }
    }
    return 0;
}

int main(int argc, char *argv[]) {
    uint16_t portid;

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Initialize EAL environment
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");

    // We need at least 2 cores enabled via -l coremask parameter now
    if (rte_lcore_count() < 2) {
        rte_exit(EXIT_FAILURE, "Error: This application requires at least 2 logical cores.\n");
    }

    // Allocate Mempool
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS, MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL) rte_exit(EXIT_FAILURE, "Cannot initialize mbuf pool\n");

    // Initialize interfaces
    RTE_ETH_FOREACH_DEV(portid) {
        if (port_init(portid, mbuf_pool) != 0) {
            rte_exit(EXIT_FAILURE, "Cannot init port %u\n", portid);
        }
    }

    /* STEP 4: Create our Multi-Producer/Multi-Consumer Lockless Ring */
    packet_ring = rte_ring_create("PACKET_RING", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (packet_ring == NULL) rte_exit(EXIT_FAILURE, "Cannot create packet ring layer\n");

    /* STEP 5: Launch threads on assigned cores */
    uint8_t master_core = rte_get_main_lcore();
    uint8_t worker_core = rte_get_next_lcore(master_core, 0, 0);

    // Launch Consumer Thread on our second designated core
    rte_eal_remote_launch(lcore_tx, NULL, worker_core);

    // Run Producer logic directly on Main core thread
    lcore_rx(NULL);

    // Block until remote core terminates completely following Ctrl+C
    rte_eal_mp_wait_lcore();

    /* Clean Up Rings and Ports */
    rte_ring_free(packet_ring);
    RTE_ETH_FOREACH_DEV(portid) {
        printf("Closing port %u...\n", portid);
        rte_eth_dev_stop(portid);
    }
    printf("DPDK Pipeline terminated cleanly.\n");
    return 0;
}

