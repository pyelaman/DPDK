#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <signal.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_lcore.h>
#include "alkira_state.h"

#define NUM_MBUFS 524287
#define MBUF_CACHE_SIZE 512
#define BURST_SIZE 32

volatile bool force_quit = false;
struct rte_mempool *pktmbuf_pool = NULL;

/* Reference external functional entries developed in previous stages */
extern bool initialize_alkira_session_table(void);
extern void process_alkira_pipeline_with_state(uint16_t port_id, uint16_t queue_id, struct rte_mbuf **pkts, uint16_t nb_pkts);
extern int async_gc_sweep_thread(void *arg);

/* Graceful termination signal interceptor mapping */
static void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\n\nSignal %d received, preparing thread shutdown sequence...\n", signum);
        force_quit = true;
    }
}

/* Base structural port configuration layout */
static const struct rte_eth_conf port_conf_default = {
    .rxmode = {
        .max_lro_pkt_size = RTE_ETHER_MAX_LEN,
    },
};

/* Configures and wakes up the hardware poll mode driver (PMD) interfaces */
static inline int port_init(uint16_t port, struct rte_mempool *mbuf_pool) {
    struct rte_eth_conf port_conf = port_conf_default;
    const uint16_t rx_rings = 1, tx_rings = 1;
    uint16_t nb_rxd = 1024;
    uint16_t nb_txd = 1024;
    int retval;

    if (!rte_eth_dev_is_valid_port(port)) return -1;

    /* 1. Allocate resources and configure hardware queues */
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0) return retval;

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval != 0) return retval;

    /* 2. Provision Rx Ring Buffers onto current execution NUMA sockets */
    retval = rte_eth_rx_queue_setup(port, 0, nb_rxd, rte_eth_dev_socket_id(port), NULL, mbuf_pool);
    if (retval < 0) return retval;

    /* 3. Provision Tx Ring Buffers onto current execution NUMA sockets */
    struct rte_eth_txconf txconf = {0};
    retval = rte_eth_tx_queue_setup(port, 0, nb_txd, rte_eth_dev_socket_id(port), &txconf);
    if (retval < 0) return retval;

    /* 4. Start the physical network controller driver engine */
    retval = rte_eth_dev_start(port);
    if (retval < 0) return retval;

    /* Enable Promiscuous parsing to guarantee transit processing viability */
    rte_eth_promiscuous_enable(port);
    return 0;
}

/* Core execution entry loop mapped to dedicated data plane lcores */
static int lcore_worker_launch(__attribute__((unused)) void *arg) {
    uint16_t port;
    struct rte_mbuf *pkts_burst[BURST_SIZE];
    uint16_t lcore_id = rte_lcore_id();

    printf("[LCORE %u] Processing thread active. Launching polling matrix.\n", lcore_id);

    while (!force_quit) {
        /* Run a standard Poll Mode Driver (PMD) check loop across all available valid interfaces */
        RTE_ETH_FOREACH_DEV(port) {
            // Fetch packet bursts from Hardware Queue 0
            uint16_t nb_rx = rte_eth_rx_burst(port, 0, pkts_burst, BURST_SIZE);
            
            if (likely(nb_rx > 0)) {
                /* Hand over the thread burst pointer to the lockless vector lookup pipeline */
                process_alkira_pipeline_with_state(port, 0, pkts_burst, nb_rx);
            }
        }
    }
    return 0;
}

int main(int argc, char *argv[]) {
    int retval;
    uint16_t port_id;
    uint16_t nb_ports;

    /* 1. Global System EAL Framework Init Initialization */
    retval = rte_eal_init(argc, argv);
    if (retval < 0) {
        rte_exit(EXIT_FAILURE, "Error: Invalid DPDK EAL bootstrapping parameters.\n");
    }
    argc -= retval;
    argv += retval;

    // Register active lifecycle handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    nb_ports = rte_eth_dev_count_avail();
    if (nb_ports < 2) {
        rte_exit(EXIT_FAILURE, "Error: Transit operations require a minimum of 2 physical network links.\n");
    }

    /* 2. Core Mempool Layer Allocation Matrix Initialization */
    pktmbuf_pool = rte_pktmbuf_pool_create(
        "ALKIRA_MBUF_POOL", 
        NUM_MBUFS, 
        MBUF_CACHE_SIZE, 
        0, 
        RTE_MBUF_DEFAULT_BUF_SIZE, 
        rte_socket_id()
    );

    if (pktmbuf_pool == NULL) {
        rte_exit(EXIT_FAILURE, "Critical Error: Global pktmbuf pool memory allocation failed.\n");
    }

    /* 3. Scalable Core Hash Table Memory Setup Configuration */
    printf("[ALKIRA BOOT ENGINE] Allocating 4-million lockless concurrency state slots...\n");
    if (!initialize_alkira_session_table()) {
        rte_exit(EXIT_FAILURE, "Critical Error: Unable to assign and register multi-tenant lockless map.\n");
    }
    printf("[ALKIRA BOOT ENGINE] Multi-million session lookup tables successfully prepared.\n");

    /* 4. Peripheral Port Validation Loop Setup */
    RTE_ETH_FOREACH_DEV(port_id) {
        if (port_init(port_id, pktmbuf_pool) != 0) {
            rte_exit(EXIT_FAILURE, "Critical Error: Failed initialization on Port ID: %u\n", port_id);
        }
        printf("[PORT CONFIGURED] Port %u initialized and running at line-rate tracking parameters.\n", port_id);
    }

    /* Step 5: Boot separate parallel jobs to balance data paths vs maintenance routines */
    uint32_t lcore_worker_id;
    uint32_t gc_lcore_id = rte_get_next_lcore(rte_get_main_lcore(), 1, 0);

    if (gc_lcore_id == RTE_MAX_LCORE) {
        rte_exit(EXIT_FAILURE, "Error: Insufficient core layout provisioned. \
			GC requires a dedicated processing thread.\n");
    }

    /* 1. Fire up background asynchronous monitoring engine on its own lcore */
    rte_eal_remote_launch(async_gc_sweep_thread, NULL, gc_lcore_id);

    /* 2. Run data path workers concurrently on remaining allocated cores */
    RTE_LCORE_FOREACH_WORKER(lcore_worker_id) {
        if (lcore_worker_id != gc_lcore_id) {
            rte_eal_remote_launch(lcore_worker_launch, NULL, lcore_worker_id);
        }
    }

    /* 5. Parallel Multi-core Pipeline Multi-thread Activation Execution */
    // Spawns the processing loop function across all allocated worker lcores (configured via e.g., -c or -l flags)
    // rte_eal_mp_remote_launch(lcore_worker_launch, NULL, CALL_MAIN);

    /* 6. Graceful Recovery & Cleanup Core Teardown Sequence */
    rte_eal_mp_wait_lcore();

    printf("\nData plane threads exited cleanly. Freeing network resources...\n");
    RTE_ETH_FOREACH_DEV(port_id) {
        printf("Stopping device channel port %u...\n", port_id);
        rte_eth_dev_stop(port_id);
        rte_eth_dev_close(port_id);
    }

    rte_eal_cleanup();
    printf("[TERMINATION COMPLETION] Alkira CXP pipeline context successfully unmounted.\n");

    return 0;
}

