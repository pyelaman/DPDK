1. Multi-Tenant Route Target (RT) Constraint Filtering

   By default, a BGP Route Reflector (RR) broadcasts every received EVPN route to every 
   single leaf node (provider edge or virtual gateway). 
   In a multi-tenant cloud fabric, this is highly inefficient: 
   a gateway handling traffic only for Tenant A should never waste CPU cycles parsing 
   or storing routing updates for Tenant B.

    The Strategy: Implement BGP Route Target Constraining. Leaf nodes use a specialized 
    address family (AFI=1, SAFI=132) to advertise to the Route Reflector exactly which 
    tenant Route Targets they possess locally.

    The Scaling Impact: The Route Reflector builds a dynamic distribution tree. 
    It filters out unneeded updates at the source, sending a tenant's EVPN routes only 
    to the specific cloud gateways that service that tenant. 
    This prevents leaf node routing tables from exhausting their memory.

2. Direct L3 Routing via EVPN Route Type 5 (Prefix Routes)

    In early EVPN deployments, networks relied heavily on Route Type 2 (MAC/IP Advertisement) 
    to advertise individual host addresses. 
    At cloud scale, advertising every individual virtual machine or container IP as a 
    /32 or /128 route explodes the size of the control plane database.

        The Strategy: Decouple the control plane from individual host MACs by heavily 
        utilizing EVPN Route Type 5 (IP Prefix Routes).

        Instead of advertising 10,000 individual host paths inside a cloud subnet, 
        the gateway aggregates them at the cloud edge and advertises a single summarized prefix 
        (e.g., 10.0.0.0/16) wrapped inside an EVPN Type 5 NLRI (Network Layer Reachability).

        The Scaling Impact: This reduces the BGP routing table size by orders of 
        magnitude and insulates the core network from "route flapping" caused by 
        individual cloud instances spinning up or down.

3. Partitioned and Hierarchical Route Reflector (RR) Clusters

    A single centralized Route Reflector cluster will eventually hit a scale bottleneck 
    at millions of QPS. To scale horizontally, the control plane architecture must partition 
    the BGP state.

        Tenant-Based Sharding: Route Reflectors are split into discrete clusters dedicated 
        to specific groups of tenants. 
        For example, RR Cluster 1 handles Tenants 1–500, while RR Cluster 2 handles Tenants 501–1000.

        Region-Based Hierarchical Topology: Local Route Reflectors handle intra-region cloud 
        exchange paths (e.g., US-East-1 connections) and use an upper-tier Inter-Region RR Mesh 
        to pass aggregated multi-cloud routes across continents. 
        This keeps regional routing anomalies from impacting global convergence times.

4. Proxy ARP/ND and MAC Address Suppression

    When a tenant application triggers an IP lookup, standard networks broadcast an ARP request 
    across the layer 2 domain. If left unchecked, these broadcast packets flood the entire 
    multi-tenant fabric, consuming valuable data-plane bandwidth.

        The Strategy: Turn on Proxy ARP and Neighbor Discovery (ND) Suppression on all 
        virtual fabric interfaces.

        When a gateway learns a MAC-to-IP binding via an incoming EVPN Type 2 route, 
        it caches that binding locally in its user-space data path. 
        When another host sends an ARP request, the local gateway intercepts it and 
        replies directly with the target MAC from its cache, suppressing the broadcast frame entirely.

        The Scaling Impact: This eliminates broadcast, unknown unicast, and multicast (BUM) 
        traffic storms across the multi-cloud network, keeping data-path performance deterministic.

5. Virtual Routing and Forwarding (VRF) Route Leak Containment

    Alkira allows tenants to configure shared services (e.g., steering internet-bound traffic 
    through a shared firewall or connecting to a shared corporate database). 
    In BGP EVPN, this requires Route Leaking across different tenant VRFs.

        The Strategy: Instead of copying routes completely from VRF-A to VRF-B 
        (which doubles the memory footprint per leaked route), 
        implement Hierarchical Context Inter-Lookup.

        The control plane maintains a single, unified master transit VRF. 
        When a tenant packet requires a shared service, the data-path policy engine 
        changes the routing token on the fly, pointing the lookup vector directly 
        to the shared service VRF without replicating the actual BGP routing entries 
        across tenant contexts.

Checklist of scaling choices
============================

    1. Prefix vs. Host Routes: Emphasize that your default multi-cloud architecture prioritizes 
       Type 5 prefix routes at the cloud boundary, reserving Type 2 MAC/IP routes strictly 
       for cases where Layer 2 stretched subnets are explicitly required by legacy on-premise 
       migrations.

    2. Next-Hop Invalidation Speeds: Explain that during a cloud failover, relying on individual 
       route withdrawals takes too long. By using EVPN mass withdraw capabilities 
       (triggered via changes to the BGP Next-Hop or EVPN Ethernet Segment Identifier - ESI), 
       the entire fabric can invalidate thousands of tenant routes in a single BGP update cycle.

    3. Graceful Restart and BGP Keepalives: Under extreme multi-million packet loads, 
       control packets can occasionally be dropped. Enforcing BGP Graceful Restart (RFC 4724) 
       ensures that if a control-plane routing daemon temporarily restarts or stalls, 
       the high-performance user-space data path (like the DPDK conntrack engine we built) 
       keeps forwarding active traffic without interruption.
