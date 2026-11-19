#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

/* Global Memory Pool for Packet Buffers */
struct rte_mempool *mbuf_pool = NULL;

/* Simple port configuration structure */
static struct rte_eth_conf port_conf_default = {
    .rxmode = {
        .max_lro_pkt_size = RTE_ETHER_MAX_LEN,
    },
};

/* Function to initialize a single ethernet port */
static inline int port_init(uint16_t port, struct rte_mempool *mbuf_pool) {
    struct rte_eth_conf port_conf = port_conf_default;
    const uint16_t rx_rings = 1, tx_rings = 1;
    int retval;
    uint16_t q;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf txconf;

    if (!rte_eth_dev_is_valid_port(port)) return -1;

    /* Get hardware device information */
    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0) return retval;

    /* Configure the Ethernet device */
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval < 0) return retval;

    /* Set up 1 RX queue */
    for (q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE,
                rte_eth_dev_socket_id(port), NULL, mbuf_pool);
        if (retval < 0) return retval;
    }

    /* Set up 1 TX queue */
    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;
    for (q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE,
                rte_eth_dev_socket_id(port), &txconf);
        if (retval < 0) return retval;
    }

    /* Start the Ethernet port */
    retval = rte_eth_dev_start(port);
    if (retval < 0) return retval;

    /* Enable promiscuous mode so we capture ALL incoming packets */
    retval = rte_eth_promiscuous_enable(port);
    if (retval != 0) return retval;

    printf("Port %u successfully initialized.\n", port);
    return 0;
}

/* The continuous data path processing loop */
static __rte_noreturn void lcore_main(void) {
    uint16_t port;

    /* Check that we have exactly 2 ports to route between */
    RTE_ETH_FOREACH_DEV(port) {
        if (rte_eth_dev_socket_id(port) > 0 && rte_eth_dev_socket_id(port) != (int)rte_socket_id()) {
            printf("Warning: Port %u is on a remote NUMA node.\n", port);
        }
    }

    printf("\nCore %u processing packets. [Ctrl+C to quit]\n", rte_lcore_id());

    /* Run-to-completion processing loop */
    for (;;) {
        RTE_ETH_FOREACH_DEV(port) {
            struct rte_mbuf *bufs[BURST_SIZE];
            
            /* Target port is the alternate interface (0 -> 1, 1 -> 0) */
            uint16_t dst_port = port ^ 1; 

            /* 1. Read burst of packets from the RX queue */
            const uint16_t nb_rx = rte_eth_rx_burst(port, 0, bufs, BURST_SIZE);

            if (unlikely(nb_rx == 0)) continue;

            /* 2. Process Layer 2 payload (In a real app, logic goes here) */
            // For this basic example, we treat it as a direct hardware wire/bridge.

            /* 3. Emit burst of packets out the TX queue of the destination port */
            const uint16_t nb_tx = rte_eth_tx_burst(dst_port, 0, bufs, nb_rx);

            /* 4. Memory Management: Free packets that failed to send to avoid leaks */
            if (unlikely(nb_tx < nb_rx)) {
                uint16_t buf;
                for (buf = nb_tx; buf < nb_rx; buf++) {
                    rte_pktmbuf_free(bufs[buf]);
                }
            }
        }
    }
}

int main(int argc, char *argv[]) {
    uint16_t portid;

    /* Step 1: Initialize the Environment Abstraction Layer (EAL) */
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    argc -= ret;
    argv += ret;

    /* Verify we have at least 2 ports bound to DPDK */
    uint16_t nb_ports = rte_eth_dev_count_avail();
    if (nb_ports < 2) {
        rte_exit(EXIT_FAILURE, "Error: Standard execution requires at least 2 DPDK ports.\n");
    }

    /* Step 2: Allocate the memory pool for holding packets */
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

    if (mbuf_pool == NULL) rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

    /* Step 3: Initialize all available ethernet ports */
    RTE_ETH_FOREACH_DEV(portid) {
        if (port_init(portid, mbuf_pool) != 0) {
            rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n", portid);
        }
    }

    /* Step 4: Run the data path execution thread loop */
    lcore_main();

    return 0;
}

