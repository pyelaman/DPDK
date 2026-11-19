#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_prefetch.h>
#include <rte_branch_prediction.h>

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32
#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

static const struct rte_eth_conf port_conf_default = {
    .rxmode = {
        .max_lro_pkt_size = RTE_ETHER_MAX_LEN,
    },
};

/*
 * Zero-Copy Fast-Path Core Processing Ring Loop Architecture
 */
static __rte_noreturn void fast_path_zero_copy_worker(struct rte_mempool *mbuf_pool, uint16_t port_id) {
    struct rte_mbuf *mbufs[BURST_SIZE];
    uint16_t nb_rx, i;

    RTE_ETH_FOREACH_DEV(port_id) {
        if (rte_eth_dev_socket_id(port_id) > 0 && rte_eth_dev_socket_id(port_id) != (int)rte_socket_id()) {
            printf("[WARN] Port %u is on a remote NUMA node. Expect performance degradation.\n", port_id);
        }
    }

    printf("[INFO] Fast-Path Execution Engine fully active on Core: %u\n", rte_lcore_id());

    for (;;) {
        // Read packet bursts directly from the NIC receive descriptors into the mbuf pool
        nb_rx = rte_eth_rx_burst(port_id, 0, mbufs, BURST_SIZE);

        if (unlikely(nb_rx == 0)) {
            continue;
        }

        // Prefetch initial memory cache lines for the first few packets in the batch
        for (i = 0; i < RTE_MIN(nb_rx, 4); i++) {
            rte_prefetch0(rte_pktmbuf_mtod(mbufs[i], void *));
            rte_prefetch0(mbufs[i]);
        }

        // Process packets using pipelined prefetching to mask memory lookup latencies
        for (i = 0; i < nb_rx; i++) {
            if (likely(i + 4 < nb_rx)) {
                // Prefetch packet data structure metadata 4 slots ahead
                rte_prefetch0(mbufs[i + 4]);
                // Prefetch packet raw frame data pointer payload payload lines
                rte_prefetch0(rte_pktmbuf_mtod(mbufs[i + 4], void *));
            }

            struct rte_mbuf *m = mbufs[i];
            
            /* 
             * ZERO-COPY PROCESSING ENGINE BLOCK
             * We do not copy data. We modify headers in-place by manipulating pointer references.
             */
            uint8_t *data_payload = rte_pktmbuf_mtod(m, uint8_t *);
            
            // Example zero-copy inline optimization action: Swap Source and Destination MAC pointers
            uint64_t *mac_ptr = (uint64_t *)data_payload;
            uint64_t temp_mac = mac_ptr[0];
            mac_ptr[0] = mac_ptr[1];
            mac_ptr[1] = temp_mac;
        }

        // Transmit the modified packet burst directly back to the physical wire
        uint16_t nb_tx = rte_eth_tx_burst(port_id, 0, mbufs, nb_rx);

        // Safely release any untransmitted packets back to the original mempool to prevent memory leaks
        if (unlikely(nb_tx < nb_rx)) {
            for (i = nb_tx; i < nb_rx; i++) {
                rte_pktmbuf_free(mbufs[i]);
            }
        }
    }
}

int main(int argc, char *argv[]) {
    struct rte_mempool *mbuf_pool;
    uint16_t port_id = 0;
    int ret;

    // Initialize the Environment Abstraction Layer (EAL)
    ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_exit(EXIT_FAILURE, "Error initializing EAL environment.\n");

    argc -= ret;
    argv += ret;

    // Allocate a lockless hugepage memory pool for multi-gigabit packet handling
    mbuf_pool = rte_pktmbuf_pool_create("ZERO_COPY_POOL", NUM_MBUFS,
                                        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
                                        rte_socket_id());
    if (mbuf_pool == NULL) rte_exit(EXIT_FAILURE, "Cannot initialize mbuf pool storage.\n");

    // Configure network interface properties
    struct rte_eth_conf port_conf = port_conf_default;
    if (rte_eth_dev_configure(port_id, 1, 1, &port_conf) < 0) {
        rte_exit(EXIT_FAILURE, "Cannot configure Ethernet interface port %u\n", port_id);
    }

    // Set up ring queues linked directly to our lockless memory pool allocations
    if (rte_eth_rx_queue_setup(port_id, 0, RX_RING_SIZE, rte_eth_dev_socket_id(port_id), NULL, mbuf_pool) < 0) {
        rte_exit(EXIT_FAILURE, "RX Queue initialization failure.\n");
    }

    if (rte_eth_tx_queue_setup(port_id, 0, TX_RING_SIZE, rte_eth_dev_socket_id(port_id), NULL) < 0) {
        rte_exit(EXIT_FAILURE, "TX Queue initialization failure.\n");
    }

    // Start the network interface card (NIC) hardware pipelines
    ret = rte_eth_dev_start(port_id);
    if (ret < 0) rte_exit(EXIT_FAILURE, "Failed to start interface device. Error: %d\n", ret);

    rte_eth_promiscuous_enable(port_id);

    // Launch the worker loop thread on the designated core
    fast_path_zero_copy_worker(mbuf_pool, port_id);

    return 0;
}

