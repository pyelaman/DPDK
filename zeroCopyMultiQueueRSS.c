#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_prefetch.h>
#include <rte_branch_prediction.h>
#include <rte_lcore.h>

#define MBUFS_PER_CORE 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32
#define RING_SIZE 1024
#define MAX_CORES 16

/* 
 * Thread context structure mapping individual queues to dedicated lcores 
 */
struct lcore_queue_config {
    uint16_t port_id;
    uint16_t rx_queue_id;
    uint16_t tx_queue_id;
    struct rte_mempool *mbuf_pool;
} __rte_cache_aligned;

static struct lcore_queue_config lcore_configs[MAX_CORES];

/*
 * Symmetrical Toeplitz Hash Key (40 Bytes)
 * Ensures that forward and reverse paths of a TCP flow hash to the same queue
 */
static uint8_t rss_symmetric_key[40] = {
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A
};

/*
 * Pinned Worker Thread Execution Loop
 */
static int multi_queue_worker_loop(void *arg) {
    uint32_t lcore_id = rte_lcore_id();
    struct lcore_queue_config *config = &lcore_configs[lcore_id];
    struct rte_mbuf *mbufs[BURST_SIZE];
    uint16_t nb_rx, nb_tx, i;

    if (config->mbuf_pool == NULL) {
        printf("[INFO] Core %u unassigned. Entering low-power sleep.\n", lcore_id);
        return 0;
    }

    printf("[FAST-PATH] Core %u processing Port %u, RX Q: %u, TX Q: %u\n", 
           lcore_id, config->port_id, config->rx_queue_id, config->tx_queue_id);

    for (;;) {
        // Read packet bursts exclusively from this core's assigned hardware RX queue
        nb_rx = rte_eth_rx_burst(config->port_id, config->rx_queue_id, mbufs, BURST_SIZE);

        if (unlikely(nb_rx == 0)) {
            continue;
        }

        // Prefetch initial frames
        for (i = 0; i < RTE_MIN(nb_rx, 4); i++) {
            rte_prefetch0(rte_pktmbuf_mtod(mbufs[i], void *));
            rte_prefetch0(mbufs[i]);
        }

        // In-line parsing / transformations using pipelined prefetching
        for (i = 0; i < nb_rx; i++) {
            if (likely(i + 4 < nb_rx)) {
                rte_prefetch0(mbufs[i + 4]);
                rte_prefetch0(rte_pktmbuf_mtod(mbufs[i + 4], void *));
            }

            struct rte_mbuf *m = mbufs[i];
            uint8_t *data = rte_pktmbuf_mtod(m, uint8_t *);
            
            // Execute Zero-Copy packet adjustments...
            // (e.g., updating inner fields, routing tags, or encapsulation states)
            data[0] = data[0]; 
        }

        // Transmit out of the corresponding hardware TX queue without cross-core locking contention
        nb_tx = rte_eth_tx_burst(config->port_id, config->tx_queue_id, mbufs, nb_rx);

        // Clear drops in place if egress buffer ring experiences backpressure
        if (unlikely(nb_tx < nb_rx)) {
            for (i = nb_tx; i < nb_rx; i++) {
                rte_pktmbuf_free(mbufs[i]);
            }
        }
    }
    return 0;
}

int main(int argc, char *argv[]) {
    uint16_t port_id = 0;
    uint16_t nb_lcores = 0;
    uint32_t lcore_id;
    int ret;

    ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_exit(EXIT_FAILURE, "EAL initialization failed.\n");

    // Count available active worker cores assigned via EAL coremasks (-c or -l)
    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        nb_lcores++;
    }

    if (nb_lcores == 0 || nb_lcores > MAX_CORES) {
        rte_exit(EXIT_FAILURE, "Invalid core layout configuration. Support range: 1 to %d worker cores.\n", MAX_CORES);
    }

    // Configure the network adapter interface for Multi-Queue RSS operation
    struct rte_eth_conf port_conf = {
        .rxmode = {
            .mq_mode = RTE_ETH_MQ_RX_RSS, // Enable hardware Receive Side Scaling
        },
        .rx_adv_conf = {
            .rss_conf = {
                .rss_key = rss_symmetric_key,
                .rss_key_len = 40,
                // Hash across both IPv4 addresses and TCP L4 ports for fine-grained entropy distribution
                .rss_hf = RTE_ETH_RSS_NONFRAG_IPV4_TCP, 
            },
        },
        .txmode = {
            .mq_mode = RTE_ETH_MQ_TX_NONE,
        },
    };

    // Configure the hardware port to map an equal number of RX and TX queues to our worker thread pool
    if (rte_eth_dev_configure(port_id, nb_lcores, nb_lcores, &port_conf) < 0) {
        rte_exit(EXIT_FAILURE, "Cannot configure interface port %u with %u queues.\n", port_id, nb_lcores);
    }

    uint16_t current_queue_index = 0;
    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        char pool_name[32];
        snprintf(pool_name, sizeof(pool_name), "MBUF_POOL_C%u", lcore_id);

        // Allocate isolated, local mempools per core to prevent NUMA bus and allocator lock contention
        struct rte_mempool *local_pool = rte_pktmbuf_pool_create(
            pool_name, MBUFS_PER_CORE, MBUF_CACHE_SIZE, 0, 
            RTE_MBUF_DEFAULT_BUF_SIZE, rte_lcore_to_socket_id(lcore_id)
        );

        if (!local_pool) rte_exit(EXIT_FAILURE, "Failed to instantiate mempool: %s\n", pool_name);

        // Bind Queue ID mappings to this thread's configuration footprint
        lcore_configs[lcore_id].port_id = port_id;
        lcore_configs[lcore_id].rx_queue_id = current_queue_index;
        lcore_configs[lcore_id].tx_queue_id = current_queue_index;
        lcore_configs[lcore_id].mbuf_pool = local_pool;

        // Hardware Queue Setup
        if (rte_eth_rx_queue_setup(port_id, current_queue_index, RING_SIZE, 
                                   rte_eth_dev_socket_id(port_id), NULL, local_pool) < 0) {
            rte_exit(EXIT_FAILURE, "Failed setting up RX Queue: %u\n", current_queue_index);
        }

        if (rte_eth_tx_queue_setup(port_id, current_queue_index, RING_SIZE, 
                                   rte_eth_dev_socket_id(port_id), NULL) < 0) {
            rte_exit(EXIT_FAILURE, "Failed setting up TX Queue: %u\n", current_queue_index);
        }

        current_queue_index++;
    }

    // Start interface processing engines
    if (rte_eth_dev_start(port_id) < 0) rte_exit(EXIT_FAILURE, "Failed to start interface.\n");
    rte_eth_promiscuous_enable(port_id);

    // Launch parallel worker loops across all designated, pinned execution threads
    rte_eal_mp_remote_launch(multi_queue_worker_loop, NULL, CALL_MAIN);
    
    // Wait for worker pipelines to gracefully stop (or handle cleanup loops)
    rte_eal_mp_wait_lcore();

    return 0;
}

