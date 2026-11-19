#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_mbuf.h>
#include <rte_hash.h>
#include <rte_fbk_hash.h>
#include <rte_jhash.h>
#include <rte_acl.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_ether.h>
#include <rte_mempool.h>

#include "dataplane_structs.h"

#define BURST_SIZE 32

/* Allocate Global Tables to satisfy worker references */
struct rte_hash *fast_path_hash_table = NULL;
struct rte_acl_ctx *slow_path_acl_ctx = NULL;
struct rte_mempool *flow_entry_mempool = NULL;
struct rte_mempool *pkt_mbuf_pool = NULL;

/* 1. Define ACL Field Rules exactly matching standard IPv4 parameters */
struct rte_acl_field_def acl_fields[5] = {
    { .type = RTE_ACL_FIELD_TYPE_BITMASK, .size = 1, .field_index = 0, .input_index = 0, .offset = offsetof(struct rte_ipv4_hdr, next_proto_id) },
    { .type = RTE_ACL_FIELD_TYPE_MASK,    .size = 4, .field_index = 1, .input_index = 1, .offset = offsetof(struct rte_ipv4_hdr, src_addr) },
    { .type = RTE_ACL_FIELD_TYPE_MASK,    .size = 4, .field_index = 2, .input_index = 2, .offset = offsetof(struct rte_ipv4_hdr, dst_addr) },
    { .type = RTE_ACL_FIELD_TYPE_RANGE,   .size = 2, .field_index = 3, .input_index = 3, .offset = sizeof(struct rte_ipv4_hdr) + offsetof(struct rte_tcp_hdr, src_port) },
    { .type = RTE_ACL_FIELD_TYPE_RANGE,   .size = 2, .field_index = 4, .input_index = 3, .offset = sizeof(struct rte_ipv4_hdr) + offsetof(struct rte_tcp_hdr, dst_port) }
};

RTE_ACL_RULE_DEF(acl_rule, 5);

/* Initialization routine for your fast-path Cuckoo Hash Table */
static void init_hash_table(void) {
    struct rte_hash_parameters hash_params = {
        .name = "FAST_PATH_FLOW_TABLE",
        .entries = 1024,
        .key_len = sizeof(struct flow_key),
        .hash_func = rte_jhash,
        .hash_func_init_val = 0,
        .socket_id = (int)rte_socket_id()
    };
    fast_path_hash_table = rte_hash_create(&hash_params);
    if (!fast_path_hash_table) rte_exit(EXIT_FAILURE, "Failed to create fast-path hash table\n");
}

/* Initialization routine for slow-path structural ACL Context Trees */
static void init_acl_ctx(void) {
    struct rte_acl_param acl_params = {
        .name = "SLOW_PATH_ACL_FIREWALL",
        .socket_id = (int)rte_socket_id(),
        .rule_size = RTE_ACL_RULE_SZ(5),
        .max_rule_num = 128
    };
    slow_path_acl_ctx = rte_acl_create(&acl_params);
    if (!slow_path_acl_ctx) rte_exit(EXIT_FAILURE, "Failed to create ACL context\n");

    if (rte_acl_set_ctx_classify(slow_path_acl_ctx, RTE_ACL_CLASSIFY_SCALAR) < 0) { // Fallback scalar mode safe inside KVM sandbox
        rte_exit(EXIT_FAILURE, "Failed to set scalar classification mode\n");
    }

    /* Inject one default sample firewall rule allowing 10.0.0.X subnets */
    struct acl_rule sample_rule = {
        .data = { .userdata = VERDICT_FORWARD, .priority = 100, .category_mask = 1 },
        .field[0] = { .value.u8 = IPPROTO_TCP, .mask_range.u8 = 0xFF },
        .field[1] = { .value.u32 = RTE_IPV4(10, 0, 0, 0), .mask_range.u32 = 24 }, // 10.0.0.0/24 Match
        .field[2] = { .value.u32 = 0, .mask_range.u32 = 0 },                     // Any Destination IP
        .field[3] = { .value.u16 = 0, .mask_range.u16 = 0xFFFF },                // Any Source Port
        .field[4] = { .value.u16 = 0, .mask_range.u16 = 0xFFFF }                 // Any Destination Port
    };

    if (rte_acl_add_rules(slow_path_acl_ctx, (struct rte_acl_rule *)&sample_rule, 1) < 0) {
        rte_exit(EXIT_FAILURE, "Failed to add rules to ACL context\n");
    }

    struct rte_acl_config acl_cfg = {
        .num_categories = 1,
        .num_fields = 5,
        .defs = {
            { .type = RTE_ACL_FIELD_TYPE_BITMASK, .size = 1, .field_index = 0, .input_index = 0, .offset = offsetof(struct rte_ipv4_hdr, next_proto_id) },
            { .type = RTE_ACL_FIELD_TYPE_MASK,    .size = 4, .field_index = 1, .input_index = 1, .offset = offsetof(struct rte_ipv4_hdr, src_addr) },
            { .type = RTE_ACL_FIELD_TYPE_MASK,    .size = 4, .field_index = 2, .input_index = 2, .offset = offsetof(struct rte_ipv4_hdr, dst_addr) },
            { .type = RTE_ACL_FIELD_TYPE_RANGE,   .size = 2, .field_index = 3, .input_index = 3, .offset = sizeof(struct rte_ipv4_hdr) + offsetof(struct rte_tcp_hdr, src_port) },
            { .type = RTE_ACL_FIELD_TYPE_RANGE,   .size = 2, .field_index = 4, .input_index = 3, .offset = sizeof(struct rte_ipv4_hdr) + offsetof(struct rte_tcp_hdr, dst_port) }
        }
    };

    if (rte_acl_build(slow_path_acl_ctx, &acl_cfg) < 0) {
        rte_exit(EXIT_FAILURE, "Failed to compile ACL runtime structures\n");
    }
}

/* Helper function to extract 5-tuple from raw packet buffer memory */
static inline int extract_5tuple(struct rte_mbuf *m, struct flow_key *key) {
    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    if (eth_hdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) return -1;

    struct rte_ipv4_hdr *ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
    key->src_ip = ipv4_hdr->src_addr;
    key->dst_ip = ipv4_hdr->dst_addr;
    key->proto  = ipv4_hdr->next_proto_id;

    if (key->proto == IPPROTO_TCP) {
        struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(ipv4_hdr + 1);
        key->src_port = tcp->src_port;
        key->dst_port = tcp->dst_port;
    } else {
        key->src_port = 0; key->dst_port = 0;
    }
    return 0;
}

/* Simulated processing routine executing your conceptual pipeline architecture */
void execute_simulated_pipeline(void) {
    struct rte_mbuf *pkts[1];
    if (rte_pktmbuf_alloc_bulk(pkt_mbuf_pool, pkts, 1) < 0) return;

    /* Build a mock IPv4 packet hitting the permitted 10.0.0.5 boundary */
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(pkts[0], struct rte_ether_hdr *);
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
    ip->next_proto_id = IPPROTO_TCP;
    ip->src_addr = RTE_IPV4(10, 0, 0, 5);
    ip->dst_addr = RTE_IPV4(192, 168, 1, 1);
    struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(ip + 1);
    tcp->src_port = rte_cpu_to_be_16(1234);
    tcp->dst_port = rte_cpu_to_be_16(80);
    pkts[0]->pkt_len = 64; pkts[0]->data_len = 64;

    struct flow_key keys[1];
    const void *key_ptrs[1];
    void *flow_data[1];
    uint64_t hit_mask = 0;
    uint32_t acl_result = 0;

    extract_5tuple(pkts[0], &keys[0]);
    key_ptrs[0] = &keys[0];

    printf("\n--- ITERATION 1: Initializing packet stream ---\n");
    rte_hash_lookup_bulk_data(fast_path_hash_table, key_ptrs, 1, &hit_mask, flow_data);

    if (!(hit_mask & 1)) {
        printf("[Slow-Path Cache Miss] Running Tree-Based ACL Classification...\n");
        const uint8_t *acl_data_ptr = rte_pktmbuf_mtod(pkts[0], const uint8_t *) + sizeof(struct rte_ether_hdr);
        rte_acl_classify(slow_path_acl_ctx, &acl_data_ptr, &acl_result, 1, 1);
        printf("ACL decision parsed: %s\n", (acl_result == VERDICT_FORWARD) ? "FORWARD (1)" : "DROP (0)");

        struct flow_entry *new_entry;
        rte_mempool_get(flow_entry_mempool, (void **)&new_entry);
        new_entry->key = keys[0];
        new_entry->verdict = acl_result;
        new_entry->nat_src_ip = RTE_IPV4(172, 16, 0, 1); // Mock Translation Entry

        rte_hash_add_key_data(fast_path_hash_table, &keys[0], new_entry);
        printf("[Optimization] Connection tracking metadata loaded locklessly into Cuckoo Fast Path.\n");
    }

    printf("\n--- ITERATION 2: Matching identical incoming burst ---\n");
    hit_mask = 0;
    rte_hash_lookup_bulk_data(fast_path_hash_table, key_ptrs, 1, &hit_mask, flow_data);

    if (hit_mask & 1) {
        printf("[Fast-Path Cache Hit] Packet bypass matches signature immediately!\n");
        struct flow_entry *entry = (struct flow_entry *)flow_data[0];
        printf("Executing address translation rewrite ➔ Transferred to NAT Mapping IP: 172.16.0.1\n");
    }

    rte_pktmbuf_free(pkts[0]);
}

int main(int argc, char *argv[]) {
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_exit(EXIT_FAILURE, "EAL initialization failed\n");

    /* Create essential supporting pools */
    pkt_mbuf_pool = rte_pktmbuf_pool_create("PKT_POOL", 128, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    flow_entry_mempool = rte_mempool_create("ENTRY_POOL", 256, sizeof(struct flow_entry), 0, 0, NULL, NULL, NULL, NULL, rte_socket_id(), 0);
    
    if (!pkt_mbuf_pool || !flow_entry_mempool) rte_exit(EXIT_FAILURE, "Memory allocations failed\n");

    init_hash_table();
    init_acl_ctx();

    execute_simulated_pipeline();

    /* Clean up allocated segments */
    rte_hash_free(fast_path_hash_table);
    rte_acl_free(slow_path_acl_ctx);
    printf("\nPipeline execution workspace cleanly discharged.\n");
    return 0;
}

