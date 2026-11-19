#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <signal.h>

/* DPDK Minimal Core Infrastructure API Headers */
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_lcore.h>

#define BURST_SIZE 32
#define NUM_MBUFS 524287
#define MBUF_CACHE_SIZE 512

volatile bool force_quit = false;
struct rte_mempool *pktmbuf_pool = NULL;

/* Shared configuration mapping layout for multi-queue core bindings */
typedef struct {
    uint16_t queue_id;
} lcore_config_t;

static lcore_config_t global_core_assignments[RTE_MAX_LCORE];

/* 
 * 40-Byte Symmetric Toeplitz Hardware RSS Hash Key.
 * Mathematically guarantees that any packet pairing (e.g., A -> B vs B -> A)
 * calculates the exact same hash token, mapping both streams to the identical core.
 */
static uint8_t symmetric_rss_key[40] = {
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A
};

/* Unified Port Initialization Profile */
static const struct rte_eth_conf port_conf_default = {
    .rxmode = {
        .max_lro_pkt_size = RTE_ETHER_MAX_LEN,
        .mq_mode = RTE_ETH_MQ_RX_RSS, /* Set port multi-queue to RSS mode */
    },
    .rx_adv_conf = {
        .rss_conf = {
            .rss_key = symmetric_rss_key,
            .rss_key_len = 40,
            .rss_hf = RTE_ETH_RSS_NONFRAG_IPV4_TCP, /* Bind RSS filters to L3/L4 TCP combinations */
        },
    },
};

static void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\nSignal %d intercepted. Cleaning multi-queue execution threads...\n", signum);
        force_quit = true;
    }
}

/* --- Port Configuration Driver Matrix --- */
static inline int port_init(uint16_t port, uint16_t num_queues, struct rte_mempool *mbuf_pool) {
    struct rte_eth_conf port_conf = port_conf_default;
    uint16_t nb_rxd = 1024;
    uint16_t nb_txd = 1024;
    int retval;

    if (!rte_eth_dev_is_valid_port(port)) return -1;

    /* 1. Provision hardware channels based on active CPU core count */
    retval = rte_eth_dev_configure(port, num_queues, num_queues, &port_conf);
    if (retval != 0) return retval;

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval != 0) return retval;

    /* 2. Set up continuous localized RX queue structures */
    for (uint16_t q = 0; q < num_queues; q++) {
        retval = rte_eth_rx_queue_setup(port, q, nb_rxd, rte_eth_dev_socket_id(port), NULL, mbuf_pool);
        if (retval < 0) return retval;
    }

    /* 3. Set up continuous localized TX queue structures */
    struct rte_eth_txconf txconf = {0};
    for (uint16_t q = 0; q < num_queues; q++) {
        retval = rte_eth_tx_queue_setup(port, q, nb_txd, rte_eth_dev_socket_id(port), &txconf);
        if (retval < 0) return retval;
    }

    /* 4. Trigger full hardware activation */
    retval = rte_eth_dev_start(port);
    if (retval < 0) return retval;

    rte_eth_promiscuous_enable(port);
    return 0;
}

/* --- Isolated Core Polling Worker Loop --- */
static int lcore_worker_launch(__attribute__((unused)) void *arg) {
    uint16_t port;
    struct rte_mbuf *pkts_burst[BURST_SIZE];
    uint16_t lcore_id = rte_lcore_id();
    
    /* Dynamically bind execution track straight to assigned queue index mapping */
    uint16_t assigned_q = global_core_assignments[lcore_id].queue_id;

    printf("[LCORE %u] Processing thread active. Polling RSS Queue ID [%u]\n", lcore_id, assigned_q);

    while (!force_quit) {
        RTE_ETH_FOREACH_DEV(port) {
            uint16_t nb_rx = rte_eth_rx_burst(port, assigned_q, pkts_burst, BURST_SIZE);
            
            if (likely(nb_rx > 0)) {
                /* Demonstrate hardware symmetric RSS confirmation */
                for (uint16_t i = 0; i < nb_rx; i++) {
                    struct rte_mbuf *m = pkts_burst[i];
                    
                    /* Log incoming packet RSS hash token signature populated directly by the NIC */
                    printf("[QUEUE %u / CORE %u] Received Packet! Hardware RSS Hash Signature = [0x%08X]\n", 
                           assigned_q, lcore_id, m->hash.rss);
                    
                    /* Free the packet from memory immediately */
                    rte_pktmbuf_free(m);
                }
            }
        }
    }
    return 0;
}

/* --- Program Entry Point --- */
int main(int argc, char *argv[]) {
    int retval;
    uint16_t port_id, nb_ports, num_workers = 0;
    uint32_t lcore_id;

    /* Initialize EAL frame structures */
    retval = rte_eal_init(argc, argv);
    if (retval < 0) rte_exit(EXIT_FAILURE, "Error: Invalid DPDK boot arguments.\n");
    argc -= retval; argv += retval;

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    nb_ports = rte_eth_dev_count_avail();
    if (nb_ports == 0) rte_exit(EXIT_FAILURE, "Error: No physical network devices detected.\n");

    /* Allocate basic memory buffer tracking pool */
    pktmbuf_pool = rte_pktmbuf_pool_create("RSS_MBUF_POOL", NUM_MBUFS, MBUF_CACHE_SIZE, 0, 
		    RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

    if (pktmbuf_pool == NULL) rte_exit(EXIT_FAILURE, "Error: Global packet mempool initialization failed.\n");

    /* Calculate core distribution limits and provision queue ids cleanly */
    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        global_core_assignments[lcore_id].queue_id = num_workers;
        num_workers++;
    }
    
    if (num_workers == 0) {
	rte_exit(EXIT_FAILURE, 
	        "Error: You must provision worker cores via coremask (-c) parameter settings.\n");
    }

    /* Bind and boot up hardware ports across the determined RSS queue bounds */
    RTE_ETH_FOREACH_DEV(port_id) {
        if (port_init(port_id, num_workers, pktmbuf_pool) != 0) {
            rte_exit(EXIT_FAILURE, 
		    "Error: Port configuration failed on Port ID: %u\n", port_id);
        }
        printf("[RSS ACTIVE] Port %u configured to distribute traffic across %u queues symmetrically.\n", 
		port_id, num_workers);
    }

    /* Multi-core launch block sequence */
    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        rte_eal_remote_launch(lcore_worker_launch, NULL, lcore_id);
    }

    /* Wait block initialization loop */
    rte_eal_mp_wait_lcore();

    printf("\nWorker loops exited cleanly. Detaching port devices...\n");
    RTE_ETH_FOREACH_DEV(port_id) {
        rte_eth_dev_stop(port_id);
        rte_eth_dev_close(port_id);
    }
    rte_eal_cleanup();
    printf("[DONE] Application unmounted.\n");
    return 0;
}
