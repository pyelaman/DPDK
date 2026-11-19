#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <signal.h>

/* DPDK Infrastructure Headers */
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_lcore.h>

#define BURST_SIZE 32
#define NUM_MBUFS 524287
#define MBUF_CACHE_SIZE 512

volatile bool force_quit = false;
struct rte_mempool *pktmbuf_pool = NULL;

/* Isolated mapping tracking per worker core */
typedef struct {
    uint16_t port_id;
    uint16_t queue_id;
    bool     is_assigned;
} lcore_config_t;

static lcore_config_t global_core_assignments[RTE_MAX_LCORE];

/* 40-Byte Symmetric Toeplitz Hardware RSS Key */
static uint8_t symmetric_rss_key[40] = {
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A
};

static const struct rte_eth_conf port_conf_default = {
    .rxmode = {
        .max_lro_pkt_size = RTE_ETHER_MAX_LEN,
        .mq_mode = RTE_ETH_MQ_RX_NONE, // RTE_ETH_MQ_RX_RSS,
    },
    .rx_adv_conf = {
        .rss_conf = {
            .rss_key = NULL, // symmetric_rss_key,
            //.rss_key_len = 40,
            .rss_hf = 0, // RTE_ETH_RSS_NONFRAG_IPV4_TCP,
        },
    },
};

static void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\nSignal %d received. Shuting down loops...\n", signum);
        force_quit = true;
    }
}

/* Port Initialization Setup */
static inline int port_init(uint16_t port, uint16_t num_queues, struct rte_mempool *mbuf_pool) {
    struct rte_eth_conf port_conf = port_conf_default;
    uint16_t nb_rxd = 1024;
    uint16_t nb_txd = 1024;
    int retval;

    if (!rte_eth_dev_is_valid_port(port)) return -1;

    retval = rte_eth_dev_configure(port, num_queues, num_queues, &port_conf);
    if (retval != 0) return retval;

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval != 0) return retval;

    for (uint16_t q = 0; q < num_queues; q++) {
        retval = rte_eth_rx_queue_setup(port, q, nb_rxd, rte_eth_dev_socket_id(port), NULL, mbuf_pool);
        if (retval < 0) return retval;
    }

    struct rte_eth_txconf txconf = {0};
    for (uint16_t q = 0; q < num_queues; q++) {
        retval = rte_eth_tx_queue_setup(port, q, nb_txd, rte_eth_dev_socket_id(port), &txconf);
        if (retval < 0) return retval;
    }

    retval = rte_eth_dev_start(port);
    if (retval < 0) return retval;

    rte_eth_promiscuous_enable(port);
    return 0;
}

/* Core-Pinned Worker Loop Polling explicit Port/Queue Assignments */
static int lcore_worker_launch(__attribute__((unused)) void *arg) {
    struct rte_mbuf *pkts_burst[BURST_SIZE];
    uint16_t lcore_id = rte_lcore_id();
    
    lcore_config_t my_config = global_core_assignments[lcore_id];
    if (!my_config.is_assigned) {
        printf("[LCORE %u] Unassigned worker skipping loop.\n", lcore_id);
        return 0;
    }

    printf("[LCORE %u] Processing loop active. Monitoring Port [%u], RSS Queue ID [%u]\n", 
           lcore_id, my_config.port_id, my_config.queue_id);

    while (!force_quit) {
        // Core reads ONLY from its explicitly assigned Port and RSS queue mapping
        uint16_t nb_rx = rte_eth_rx_burst(my_config.port_id, my_config.queue_id, pkts_burst, BURST_SIZE);
        
        if (unlikely(nb_rx > 0)) {
            for (uint16_t i = 0; i < nb_rx; i++) {
                struct rte_mbuf *m = pkts_burst[i];
                
                printf("[PORT %u / QUEUE %u / CORE %u] Captured Packet! RSS Signature = [0x%08X]\n", 
                       my_config.port_id, my_config.queue_id, lcore_id, m->hash.rss);
                
                rte_pktmbuf_free(m);
            }
        }
    }
    return 0;
}

int main(int argc, char *argv[]) {
    int retval;
    uint16_t port_id, nb_ports;
    uint32_t lcore_id;

    retval = rte_eal_init(argc, argv);
    if (retval < 0) rte_exit(EXIT_FAILURE, "Error: Invalid EAL configurations.\n");
    argc -= retval; argv += retval;

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    nb_ports = rte_eth_dev_count_avail();
    if (nb_ports == 0) rte_exit(EXIT_FAILURE, "Error: No physical networks detected.\n");

    pktmbuf_pool = rte_pktmbuf_pool_create("RSS_MBUF_POOL", NUM_MBUFS, MBUF_CACHE_SIZE, 0, 
		                            RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

    if (pktmbuf_pool == NULL) rte_exit(EXIT_FAILURE, "Error: Pool allocation failed.\n");

    /* 
     * --- MATRIX MAPPER ENGINE ---
     * Dynamically map all available worker cores across multiple ports.
     * Example: 2 Ports (0 and 1), 4 Worker Cores:
     *   Core 1 -> Port 0, Queue 0
     *   Core 2 -> Port 0, Queue 1
     *   Core 3 -> Port 1, Queue 0
     *   Core 4 -> Port 1, Queue 1
     */
    uint16_t total_workers = 0;
    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        total_workers++;
    }

    if (total_workers == 0) {
        rte_exit(EXIT_FAILURE, "Error: At least 1 worker core must be passed into -c/-l flags.\n");
    }

    // Determine how many queues to allocate per physical port interface
    uint16_t queues_per_port = total_workers / nb_ports;
    if (queues_per_port == 0) {
        queues_per_port = 1; // Fallback if you have fewer cores than physical links
    }

    /* Initialize each port with its required chunk of RSS queues */
    RTE_ETH_FOREACH_DEV(port_id) {
        if (port_init(port_id, queues_per_port, pktmbuf_pool) != 0) {
            rte_exit(EXIT_FAILURE, "Error: Port setup configuration failed on ID: %u\n", port_id);
        }
        printf("[PORT CONFIGURED] Port ID %u instantiated with %u symmetric hardware queues.\n", 
			port_id, queues_per_port);
    }

    /* Assign each worker core an isolated port and queue index */
    uint16_t target_port = 0;
    uint16_t target_queue = 0;

    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        // Stop assigning if we run out of physical port channels
        if (target_port >= nb_ports) {
            break; 
        }

        global_core_assignments[lcore_id].port_id = target_port;
        global_core_assignments[lcore_id].queue_id = target_queue;
        global_core_assignments[lcore_id].is_assigned = true;

        target_queue++;
        if (target_queue >= queues_per_port) {
            target_queue = 0;
            target_port++; // Shift assigning logic forward to the next interface port
        }
    }

    /* Launch the localized multi-core thread array */
    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        rte_eal_remote_launch(lcore_worker_launch, NULL, lcore_id);
    }

    rte_eal_mp_wait_lcore();

    printf("\nThreads stopped cleanly. Releasing port hooks...\n");
    RTE_ETH_FOREACH_DEV(port_id) {
        rte_eth_dev_stop(port_id);
        rte_eth_dev_close(port_id);
    }
    rte_eal_cleanup();
    return 0;
}

