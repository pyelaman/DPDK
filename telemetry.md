
1. EVPN Control-Plane (BGP) Telemetry

Since EVPN relies on BGP to exchange reachability information via the AFI/SAFI (25/70) address family, monitoring the stability of EVPN NLRIs (Network Layer Reachability Information) is critical.

• Prefix / Route Type Advertisements & Withdrawals: Stream rates per Route Type 
  (specifically Type 2 for MAC/IP, Type 3 for IMET, and Type 5 for IP Prefixes). 
  A spike in withdrawals indicates overlay network instability or MAC flapping.

• EVPN Route Flap Damping Metrics: Number of suppressed routes or history counts per 
  Peer/VNI to isolate flapping virtual endpoints.

• BGP EVPN Capability & Session State: Standard state tracking (Established, Idle, Connect) 
  combined with memory utilization specific to the EVPN RIB.

• RIB-to-FIB Installation Latency: The delay between receiving a BGP EVPN Type 2/5 route and 
  installing it into the localized hardware forwarder (Asic table). 
  High latency impacts fast-failover performance.


2. Multi-Homing & ESI (Ethernet Segment Identifier) Metrics

For architectures leveraging EVPN Multi-Homing (All-Active or Single-Active LACP back to 
distinct leaf nodes) instead of legacy MLAG, visibility into Designated Forwarder (DF) 
election state is non-negotiable.

• DF Election State & Transitions: Streaming alerts when a node transitions from 
  Designated Forwarder (DF) to Non-DF. Frequent transitions cause transient loops or 
  blackholing for BUM traffic.

• ESI Peer Sync Status: Validation stats for Type 4 (Ethernet Segment Route) and 
  Type 1 (Ethernet Auto-Discovery Route) tracking. 
  Ensures both multi-homed leaf nodes agree on path layouts.

• Type 1 Route Mass-Withdrawal Events: Counts of ESI failover triggers. 
  High rates pinpoint underlying core/uplink physical instability causing mass overlay withdrawals.


3. VXLAN Data-Plane (VTEP) Telemetry

This layer correlates physical underlay interfaces to virtual tunnel endpoints, 
tracking how payload flows move over the Alkira transit layer or custom backbone structures.

• VTEP Peer Status and Keepalives: Streamed health metrics of remote tunnel endpoints 
  via automated underlay tracking or Bidirectional Forwarding Detection (BFD) over VXLAN.

• NVE (Network Virtual Endpoint) Interface Counters: Total bytes/packets encapsulated and 
  decapsulated per VTEP interface.

• Encapsulation/Decapsulation Error Counters: Explicit tracking of drops caused by:
	• Invalid VNI mismatches.
	• Inner/Outer frame checksum failures.
	• MTU violations (e.g., payloads exceeding boundaries due to missing MSS clamping).

4. L2VPN (Bridging / MAC-VRF) Overlay Statistics

These statistics provide visibility into Layer 2 virtual domains across the EVPN fabric.

• VNI-level MAC Address Count: Current vs. maximum scale limits of MAC addresses learned 
  per Bridge-Domain / Layer 2 VNI.

• MAC Mobility / Move Counters: The number of times a specific MAC address transitions 
  between different remote VTEPs or localized ports within a short window. 
  A high count explicitly indicates a Layer 2 Loop or IP/MAC hijacking/spoofing.

• BUM Traffic Counters per VNI: Disaggregated stream counts for Broadcast, Unknown Unicast, 
  and Multicast (BUM) traffic mapped back to the ingress VTEP replication paths 
  (Head-end Replication or Underlay Multicast groups).

5. L3VPN (Routing / IP-VRF) Overlay Statistics

These parameters track inter-subnet and multi-tenant isolated routing across the overlay.

• L3 VNI Prefixes Learned: The number of Type 5 routes active inside specific tenant VRF 
  routing containers.

• ARP / Neighbor Discovery (ND) Suppression Cache Performance:

	• Cache Hit Rate: Number of localized ARP queries resolved by the leaf switch using the 
      EVPN sync table without broadcasting.
	• Cache Miss / Punt Rate: Number of ARP packets forced to punt to the local CPU because 
      they weren't cached, indicating a potential resource starvation vector.

• Asymmetric vs. Symmetric Routing Counters: Mapped packet flows navigating between 
  multi-provider boundaries to verify that path enforcement (such as the Symmetric Traffic Director) 
  is maintaining expected trajectories.
