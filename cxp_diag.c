#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netdb.h>
#include <errno.h>

#define PACKET_SIZE 64
#define MAX_HOPS 30
#define TIMEOUT_SEC 2

// Internet Checksum Algorithm for ICMP headers
unsigned short calculate_checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

// 1. Connector Health Check (Simulating Cloud Gateway Connection Verification)
void run_connector_health_check(const char *ip_str, int port) {
    printf("\n[ALKIRA-MIRROR] Initiating Cloud Connector Health Check for %s:%d...\n", ip_str, port);
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        printf("[-] FAILED: Unable to initialize socket layer.\n");
        return;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip_str, &server_addr.sin_addr);

    // Set a quick 3-second timeout for the control-plane handshake simulation
    struct timeval timeout;
    timeout.tv_sec = 3;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        printf("[!] HEALTH CHECK STATUS: CRITICAL/DOWN\n");
        printf("    Reason: %s (Check BGP adjacency or tunnel endpoint configurations)\n", strerror(errno));
    } else {
        printf("[+] HEALTH CHECK STATUS: ONLINE/HEALTHY\n");
        printf("    Verification: Control-plane connector handshake completed successfully.\n");
        close(sock);
    }
}

// 2. Measure Node Latency (Microsecond Accurate ICMP Ping)
void run_node_latency_check(const char *ip_str) {
    printf("\n[ALKIRA-MIRROR] Measuring Core Fabric Latency to %s...\n", ip_str);

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        perror("[-] Raw Socket Creation Failed (Run with sudo / root permissions)");
        return;
    }

    struct timeval tv_out;
    tv_out.tv_sec = TIMEOUT_SEC;
    tv_out.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv_out, sizeof(tv_out));

    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    inet_pton(AF_INET, ip_str, &dest_addr.sin_addr);

    char packet[PACKET_SIZE];
    memset(packet, 0, sizeof(packet));
    
    struct icmp *icmp_hdr = (struct icmp *)packet;
    icmp_hdr->icmp_type = ICMP_ECHO;
    icmp_hdr->icmp_code = 0;
    icmp_hdr->icmp_id = getpid() & 0xFFFF;
    icmp_hdr->icmp_seq = 1;
    icmp_hdr->icmp_cksum = calculate_checksum(packet, PACKET_SIZE);

    struct timeval time_start, time_end;
    gettimeofday(&time_start, NULL);

    if (sendto(sock, packet, PACKET_SIZE, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) <= 0) {
        perror("[-] Failed to inject ICMP probe into data plane");
        close(sock);
        return;
    }

    char rcv_buffer[1024];
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);

    if (recvfrom(sock, rcv_buffer, sizeof(rcv_buffer), 0, (struct sockaddr *)&from_addr, &from_len) <= 0) {
        printf("[!] LATENCY CHECK: Destination Unreachable or Packet Dropped by Security Engine (Timeout)\n");
    } else {
        gettimeofday(&time_end, NULL);
        double rtt = (time_end.tv_sec - time_start.tv_sec) * 1000.0 + 
                     (time_end.tv_usec - time_start.tv_usec) / 1000.0;
        printf("[+] FABRIC PERFORMANCE DATA:\n");
        printf("    Round-Trip Time (RTT): %.3f ms\n", rtt);
    }
    close(sock);
}

// 3. Layer 3 Traceroute (Hop-by-Hop Fabric Path Extraction)
void run_cxp_traceroute(const char *ip_str) {
    printf("\n[ALKIRA-MIRROR] Executing Hop-by-Hop Traceroute from CXP Edge to Destination %s...\n", ip_str);

    int send_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    int recv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (send_sock < 0 || recv_sock < 0) {
        perror("[-] Raw Sockets Initialization Failed (Root permissions required)");
        return;
    }

    struct timeval tv_out;
    tv_out.tv_sec = TIMEOUT_SEC;
    tv_out.tv_usec = 0;
    setsockopt(recv_sock, SOL_SOCKET, SO_RCVTIMEO, &tv_out, sizeof(tv_out));

    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    inet_pton(AF_INET, ip_str, &dest_addr.sin_addr);

    char packet[PACKET_SIZE];
    printf("Hop #\tHop Gateway IP\t\tStatus / Response\n");
    printf("-----------------------------------------------------------------\n");

    for (int ttl = 1; ttl <= MAX_HOPS; ttl++) {
        // Increment the TTL on the outbound socket to trace each structural Layer 3 step
        if (setsockopt(send_sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
            perror("[-] Failed to increment TTL frame value");
            break;
        }

        memset(packet, 0, sizeof(packet));
        struct icmp *icmp_hdr = (struct icmp *)packet;
        icmp_hdr->icmp_type = ICMP_ECHO;
        icmp_hdr->icmp_code = 0;
        icmp_hdr->icmp_id = getpid() & 0xFFFF;
        icmp_hdr->icmp_seq = ttl;
        icmp_hdr->icmp_cksum = calculate_checksum(packet, PACKET_SIZE);

        sendto(send_sock, packet, PACKET_SIZE, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

        char rcv_buffer[1024];
        struct sockaddr_in from_addr;
        socklen_t from_len = sizeof(from_addr);

        if (recvfrom(recv_sock, rcv_buffer, sizeof(rcv_buffer), 0, (struct sockaddr *)&from_addr, &from_len) <= 0) {
            printf("%d\t*\t\t\t[Request Timed Out / Policy Blocked]\n", ttl);
        } else {
            int ip_hdr_len = 0;
            struct icmp *icmp_reply_hdr = NULL;

            // Conditional block evaluating macOS vs Linux IP Header Abstractions
            #if defined(__APPLE__) || defined(__MACH__)
                struct ip *ip_reply_hdr = (struct ip *)rcv_buffer;
                ip_hdr_len = ip_reply_hdr->ip_hl * 4;
                icmp_reply_hdr = (struct icmp *)(rcv_buffer + ip_hdr_len);
            #else
                struct iphdr *ip_reply_hdr = (struct iphdr *)rcv_buffer;
                ip_hdr_len = ip_reply_hdr->ihl * 4;
                icmp_reply_hdr = (struct icmp *)(rcv_buffer + ip_hdr_len);
            #endif

            //struct iphdr *ip_reply_hdr = (struct iphdr *)rcv_buffer;
            //struct icmp *icmp_reply_hdr = (struct icmp *)(rcv_buffer + (ip_reply_hdr->ihl * 4));

            char ip_res[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(from_addr.sin_addr), ip_res, INET_ADDRSTRLEN);

            if (icmp_reply_hdr->icmp_type == ICMP_TIMXCEED) {
                printf("%d\t%s\t\tTransit Hop Verified\n", ttl, ip_res);
            } else if (icmp_reply_hdr->icmp_type == ICMP_ECHOREPLY) {
                printf("%d\t%s\t\t[Reached Target Multi-Cloud Node]\n", ttl, ip_res);
                break; // Target node safely encountered
            } else {
                printf("%d\t%s\t\tUnrecognized Data Plane Feedback (Type: %d)\n", 
                       ttl, ip_res, icmp_reply_hdr->icmp_type);
            }
        }
    }

    close(send_sock);
    close(recv_sock);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: sudo %s <Destination IP/Connector IP>\n", argv[0]);
        return 1;
    }

    const char *target_ip = argv[1];

    // Execution sequence mirroring the Alkira Diagnostic workflow
    run_connector_health_check(target_ip, 80); // Testing standard HTTP listener port for connection health
    run_node_latency_check(target_ip);
    run_cxp_traceroute(target_ip);

    return 0;
}

