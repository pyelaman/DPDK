#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <errno.h>

#define MAX_HOPS 30
#define TIMEOUT_SEC 2
#define PACKET_SIZE 40 // 20 bytes IP + 20 bytes TCP

// Pseudo-header required to accurately calculate the TCP checksum 
struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

// Internet Checksum Algorithm
unsigned short calculate_checksum(unsigned short *ptr, int nbytes) {
    long sum;
    unsigned short oddbyte;
    short answer;

    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        oddbyte = 0;
        *((u_char *) &oddbyte) = *(u_char *) ptr;
        sum += oddbyte;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = (short) ~sum;
    return answer;
}

void run_l4_tcp_traceroute(const char *dest_ip_str, int dest_port) {
    printf("\n[ALKIRA-L4-MIRROR] Initializing Layer 4 TCP SYN Traceroute to %s:%d...\n", dest_ip_str, dest_port);

    // 1. Create a raw socket capable of custom outbound IP/TCP injection
    int send_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    // 2. Create an ICMP raw socket to capture the intermediate error responses
    int recv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    if (send_sock < 0 || recv_sock < 0) {
        perror("[-] Raw Socket Generation Failed (Execute using sudo)");
        return;
    }

    // Explicitly notify macOS/Linux that we are manually populating the IP header fields
    int one = 1;
    if (setsockopt(send_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("[-] Failed setting IP_HDRINCL");
        return;
    }

    // Define inbound network reading timeout limits
    struct timeval tv_out;
    tv_out.tv_sec = TIMEOUT_SEC;
    tv_out.tv_usec = 0;
    setsockopt(recv_sock, SOL_SOCKET, SO_RCVTIMEO, &tv_out, sizeof(tv_out));

    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(dest_port);
    inet_pton(AF_INET, dest_ip_str, &dest_addr.sin_addr);

    char packet[PACKET_SIZE];
    char rcv_buffer[1024];

    printf("Hop #\tHop Gateway IP\t\tStatus / Response\n");
    printf("-----------------------------------------------------------------\n");

    for (int ttl = 1; ttl <= MAX_HOPS; ttl++) {
        memset(packet, 0, PACKET_SIZE);

        // Map pointers to packet sections
        #if defined(__APPLE__) || defined(__MACH__)
            struct ip *ip_hdr = (struct ip *)packet;
            struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + sizeof(struct ip));
        #else
            struct iphdr *ip_hdr = (struct iphdr *)packet;
            struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + sizeof(struct iphdr));
        #endif

        // Populate Custom IP Header values
        #if defined(__APPLE__) || defined(__MACH__)
            ip_hdr->ip_hl = 5;
            ip_hdr->ip_v = 4;
            ip_hdr->ip_tos = 0;
            ip_hdr->ip_len = PACKET_SIZE; 
            ip_hdr->ip_id = htons(54321);
            ip_hdr->ip_off = 0;
            ip_hdr->ip_ttl = ttl; // Inject dynamic incremental L3 values
            ip_hdr->ip_p = IPPROTO_TCP;
            ip_hdr->ip_src.s_addr = inet_addr("10.0.2.15"); // Synthetic source or match client interface
            ip_hdr->ip_dst = dest_addr.sin_addr.s_addr;
        #else
            ip_hdr->ihl = 5;
            ip_hdr->version = 4;
            ip_hdr->tos = 0;
            ip_hdr->tot_len = htons(PACKET_SIZE);
            ip_hdr->id = htons(54321);
            ip_hdr->frag_off = 0;
            ip_hdr->ttl = ttl;
            ip_hdr->protocol = IPPROTO_TCP;
            ip_hdr->saddr = inet_addr("10.0.2.15"); 
            ip_hdr->daddr = dest_addr.sin_addr.s_addr;
        #endif

        // Populate Custom TCP Layer 4 SYN Header values
        #if defined(__APPLE__) || defined(__MACH__)
            tcp_hdr->th_sport = htons(45678); // Source port
            tcp_hdr->th_dport = htons(dest_port); // Target port
            tcp_hdr->th_seq = htonl(1);
            tcp_hdr->th_ack = 0;
            tcp_hdr->th_off = 5; // Header Size
            tcp_hdr->th_flags = TH_SYN; // Force Layer 4 SYN status flag
            tcp_hdr->th_win = htons(65535);
            tcp_hdr->th_sum = 0;
            tcp_hdr->th_urp = 0;
        #else
            tcp_hdr->source = htons(45678);
            tcp_hdr->dest = htons(dest_port);
            tcp_hdr->seq = htonl(1);
            tcp_hdr->ack_seq = 0;
            tcp_hdr->doff = 5;
            tcp_hdr->syn = 1; // Explicit TCP SYN
            tcp_hdr->window = htons(65535);
            tcp_hdr->check = 0;
            tcp_hdr->urg_ptr = 0;
        #endif

        // Build TCP Pseudo-header Checksum
        struct pseudo_header psh;
        #if defined(__APPLE__) || defined(__MACH__)
            psh.source_address = ip_hdr->ip_src.s_addr;
            psh.dest_address = ip_hdr->ip_dst.s_addr;
        #else
            psh.source_address = ip_hdr->saddr;
            psh.dest_address = ip_hdr->daddr;
        #endif
        psh.placeholder = 0;
        psh.protocol = IPPROTO_TCP;
        psh.tcp_length = htons(sizeof(struct tcphdr));

        int psh_size = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
        char *pseudogram = malloc(psh_size);
        memcpy(pseudogram, (char*)&psh, sizeof(struct pseudo_header));
        memcpy(pseudogram + sizeof(struct pseudo_header), tcp_hdr, sizeof(struct tcphdr));
        
        #if defined(__APPLE__) || defined(__MACH__)
            tcp_hdr->th_sum = calculate_checksum((unsigned short*)pseudogram, psh_size);
        #else
            tcp_hdr->check = calculate_checksum((unsigned short*)pseudogram, psh_size);
        #endif
        free(pseudogram);

        // Inject the crafted packet into the network
        sendto(send_sock, packet, PACKET_SIZE, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

        struct sockaddr_in from_addr;
        socklen_t from_len = sizeof(from_addr);
        memset(rcv_buffer, 0, sizeof(rcv_buffer));

        if (recvfrom(recv_sock, rcv_buffer, sizeof(rcv_buffer), 0, (struct sockaddr *)&from_addr, &from_len) <= 0) {
            printf("%d\t*\t\t\t[Request Timed Out / Dropped]\n", ttl);
        } else {
            int ip_hdr_len = 0;
            struct icmp *icmp_reply_hdr = NULL;

            #if defined(__APPLE__) || defined(__MACH__)
                struct ip *ip_reply_hdr = (struct ip *)rcv_buffer;
                ip_hdr_len = ip_reply_hdr->ip_hl * 4;
                icmp_reply_hdr = (struct icmp *)(rcv_buffer + ip_hdr_len);
            #else
                struct iphdr *ip_reply_hdr = (struct iphdr *)rcv_buffer;
                ip_hdr_len = ip_reply_hdr->ihl * 4;
                icmp_reply_hdr = (struct icmp *)(rcv_buffer + ip_hdr_len);
            #endif

            char ip_res[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(from_addr.sin_addr), ip_res, INET_ADDRSTRLEN);

            // Evaluate data plane responses
            if (icmp_reply_hdr->icmp_type == ICMP_TIMXCEED) {
                printf("%d\t%s\t\tTransit Hop Verified (TCP SYN Intercept)\n", ttl, ip_res);
            } else if (strcmp(ip_res, dest_ip_str) == 0) {
                // If the target host itself responds to our IP, the port handled it!
                printf("%d\t%s\t\t[Reached Target Port Via TCP Handshake]\n", ttl, ip_res);
                break;
            } else {
                printf("%d\t%s\t\tICMP Feedback Encountered (Type: %d)\n", ttl, ip_res, icmp_reply_hdr->icmp_type);
            }
        }
    }

    close(send_sock);
    close(recv_sock);
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: sudo %s <Destination IP> <Target Port (e.g. 80 or 443)>\n", argv[0]);
        return 1;
    }

    const char *target_ip = argv[1];
    int target_port = atoi(argv[2]);

    run_l4_tcp_traceroute(target_ip, target_port);

    return 0;
}
