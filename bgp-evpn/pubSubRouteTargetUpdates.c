#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#define MAX_LEAVES 4
#define TARGET_RT 20050

typedef struct {
    uint32_t leaf_id;
    bool active_rt_subscriptions[65536]; // Bitmap tracking subscription targets
} leaf_peer_t;

void register_rt_subscription(leaf_peer_t *leaf, uint32_t route_target) {
    leaf->active_rt_subscriptions[route_target] = true;
    printf("[SUBSCRIBE] Leaf Peer %u subscribed to Route Target (RT): %u\n", 
            leaf->leaf_id, route_target);
}

void process_and_advertise_evpn_route(leaf_peer_t **peers, uint32_t total_peers, 
                                      uint32_t route_prefix, uint32_t route_rt) {
    printf("\n[UPDATE] Processing EVPN Route Prefix 0x%X with attached RT: %u\n", 
            route_prefix, route_rt);
    
    // Evaluate target updates using the subscription graph index
    for (uint32_t i = 0; i < total_peers; i++) {
        if (peers[i]->active_rt_subscriptions[route_rt]) {
            printf("  --> Flooding update to Leaf Peer %u (Subscription match verified).\n", 
                   peers[i]->leaf_id);
        } else {
            printf("  --> [FILTERED] Update dropped for Leaf Peer %u. \
                   No active subscriptions for RT %u.\n", peers[i]->leaf_id, route_rt);
        }
    }
}

int main(void) {
    leaf_peer_t *leaf1 = calloc(1, sizeof(leaf_peer_t)); leaf1->leaf_id = 1;
    leaf_peer_t *leaf2 = calloc(1, sizeof(leaf_peer_t)); leaf2->leaf_id = 2;
    
    // Establish client topology profiles
    register_rt_subscription(leaf1, TARGET_RT);
    // leaf2 does not subscribe to TARGET_RT
    register_rt_subscription(leaf2, 9999); 

    leaf_peer_t *peer_mesh[2] = { leaf1, leaf2 };

    // Process a newly arrived multi-tenant update route payload
    process_and_advertise_evpn_route(peer_mesh, 2, 0x0A010100, TARGET_RT);

    free(leaf1);
    free(leaf2);
    return 0;
}

