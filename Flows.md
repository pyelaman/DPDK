
• Traditional: Wire ➔ NIC ➔ Kernel RAM ➔ CPU ➔ User RAM
• DPDK: Wire ➔ NIC ➔ User RAM (Bypasses Kernel & Interrupts)
• RDMA: Wire ➔ NIC ➔ User RAM (Bypasses Local & Remote CPU)
• GPUDirect RDMA: Wire ➔ NIC ➔ GPU VRAM (Bypasses Host CPU & Host RAM completely)

Traditional Data Path (High CPU Overhead)
=========================================
In a traditional setup, every packet triggers a hardware interrupt, 
forcing the CPU to pause its current work, drop into kernel space, 
and execute heavy memory-copy (memcpy) operations to bounce the packet through multiple memory segments.


[ Physical Network Wire ]
                   │
                   ▼
┌──────────────────────────────────────┐
│        Network Interface Card        │
│ 1. Receives raw physical bits        │
│ 2. Extracts Ethernet/IP/TCP frame    │
└──────────────────┬───────────────────┘
                   │
                   ▼ (PCIe Bus Transfer)
┌──────────────────────────────────────┐
│        Host RAM (Kernel Space)       │
│ 3. NIC issues DMA write into a       │
│    kernel-owned sk_buff structure    │
└──────────────────┬───────────────────┘
                   │
                   ▼ (Hardware Interrupt wakes up Host CPU Core)
┌──────────────────────────────────────┐
│               Host CPU               │
│ 4. Interrupt Service Routine runs    │
│ 5. CPU manual executes memcpy() to   │
│    shift data across kernel boundary │
└──────────────────┬───────────────────┘
                   │
                   ▼
┌──────────────────────────────────────┐
│         Host RAM (User Space)        │
│ 6. Packet lands in application memory│
└──────────────────────────────────────┘


Kernel Bypass Data Path (DPDK/SR-IOV)
=====================================

By introducing DPDK, we completely eliminate the host kernel and hardware interrupts. 
The CPU core is dedicated to polling the network interface memory ring directly, 
forcing the NIC to drop packets straight into pre-allocated User Space Hugepages.

       [ Physical Network Wire ]
                   │
                   ▼
┌──────────────────────────────────────┐
│  Network Interface Card (SR-IOV)     │
│ 1. Hardware parses incoming frame    │
│ 2. Routes packet directly to a       │
│   Virtual Function (VF) hardware ring│
└──────────────────┬───────────────────┘
                   │
                   ▼ (Direct PCIe DMA Write - Bypasses Kernel completely)
┌──────────────────────────────────────┐
│     Host RAM (User Space Hugepages)  │
│ 3. NIC hardware drops packet directly│
│    into application memory space     │
└──────────────────┬───────────────────┘
                   │
         ▲         │ (Zero-Copy Ring Pointer Reference)
         │         ▼
┌────────┴─────────────────────────────┐
│               Host CPU               │
│ 4. Core continuously polls the ring  │
│    via native Poll Mode Driver (PMD) │
|                                      |
│ 5. Processes packet instantly        │
└──────────────────────────────────────┘
Network Memory Fabric Data Path (RoCE/RDMA)
===========================================

With RDMA, we bypass both the local kernel and the local CPU's execution path. 
The hardware network cards on Server A and Server B communicate directly with each other's 
RAM matrices over standard Ethernet.
[ Incoming Lossless Wire (RoCE v2 Frame) ]
                           │
                           ▼
┌─────────────────────────────────────────────────────┐
│           RDMA-Capable Network Card (rNIC)          │
│ 1. Validates RoCE v2 hardware outer UDP encap       │
│ 2. Inspects RDMA header for unique Memory Key (rkey)│
│ 3. Resolves target physical memory offset in fabric │
└──────────────────────────┬──────────────────────────┘
                           │
                           ▼ (Direct PCIe DMA Write - Bypasses Host CPU & Kernel)
┌─────────────────────────────────────────────────────┐
│                 Host RAM (User Space)               │
│ 4. Hardware logic gates write packet payload strings│
│    directly into pre-registered memory boundaries   │
└─────────────────────────────────────────────────────┘
   *NOTE: Host CPU is 0% utilized. It is completely unaware a
          network transaction occurred until a work queue check.*

Ultimate Fast Path (GPUDirect RDMA / rte_gpudev)
================================================

This is the top-tier architecture utilized in modern high-frequency stream workloads and AI model cluster execution. 
By combining an RDMA network adapter with an NVIDIA GPU over the PCIe bus, 
the network stream completely skips the Host CPU and Host RAM, 
landing straight inside GPU VRAM for instantaneous manipulation.


[ Incoming Lossless Wire (RoCE v2 Frame) ]
                           │
                           ▼
┌─────────────────────────────────────────────────────┐
│           RDMA-Capable Network Card (rNIC)          │
│ 1. Decapsulates frame and extracts payload headers  │
│ 2. Recognizes target memory block belongs to GPU    │
└──────────────────────────┬──────────────────────────┘
                           │
                           ▼ (PCIe Bus Transfer - Peer-to-Peer DMA Bypass)
┌─────────────────────────────────────────────────────┐
│                 PCIe Switch Matrix                  │
│ 3. Data payload bypasses Host CPU,Host RAM entirely.│
│    Traffic is routed directly across internal lanes.│
└──────────────────────────┬──────────────────────────┘
                           │
                           ▼ (Direct VRAM Write)
┌─────────────────────────────────────────────────────┐
│           NVIDIA GPU VRAM (High-Bandwidth)          │
│ 4. Packets drop directly into CUDA memory buffers   │
│    allocated by DPDK's rte_gpudev framework         │
└──────────────────────────┬──────────────────────────┘
                           │
                           ▼ (Line Rate Parallel Processing)
┌─────────────────────────────────────────────────────┐
│                  NVIDIA GPU Cores                   │
│ 5. Thousands of CUDA execution units process the    │
│    stream instantaneously with zero latency lag     │
└─────────────────────────────────────────────────────┘



