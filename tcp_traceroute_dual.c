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
#include <sys/select.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <errno.h>

#define MAX_HOPS 30
#define TIMEOUT_SEC 2
#define PACKET_SIZE 40 

struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

unsigned short calculate_checksum(unsigned short *ptr, int nbytes) {
    long sum = 0;
    unsigned short oddbyte;
    short answer;

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

uint32_t get_local_ip_address() {
    struct ifaddrs *interfaces = NULL;
    struct ifaddrs *ifa = NULL;
    uint32_t local_ip = 0;

    if (getifaddrs(&interfaces) < 0) {
        perror("[-] Failed to query system network adapters");
        return 0;
    }

    for (ifa = interfaces; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;
        if (ifa->ifa_addr->sa_family == AF_INET) {
            uint32_t ip = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr;
            if (ip != htonl(INADDR_LOOPBACK)) {
                local_ip = ip;
                char ip_buf[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &local_ip, ip_buf, INET_ADDRSTRLEN);
                printf("[+] DISCOVERY: Found active routing interface (%s) with Local IP: %s\n", ifa->ifa_name, ip_buf);
                break;
            }
        }
    }
    freeifaddrs(interfaces);
    return local_ip;
}

int resolve_hostname(const char *hname, struct in_addr *resolved_addr) {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_RAW;

    printf("[+] DNS WRAPPER: Resolving destination domain target '%s'...\n", hname);
    int status = getaddrinfo(hname, NULL, &hints, &res);
    if (status != 0) {
        fprintf(stderr, "[-] DNS ERROR: Unable to process target domain. %s\n", gai_strerror(status));
        return -1;
    }

    struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
    *resolved_addr = ipv4->sin_addr;
    
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, resolved_addr, ip_str, INET_ADDRSTRLEN);
    printf("[+] DNS WRAPPER: Successfully matched target to IP: %s\n", ip_str);

    freeaddrinfo(res);
    return 0;
}

void run_l4_tcp_traceroute(struct in_addr dest_addr_struct, const char *dest_ip_str, int dest_port, uint32_t local_ip) {
    printf("\n[ALKIRA-L4-MIRROR] Initializing Dual-Socket Layer 4 TCP SYN Traceroute to %s:%d...\n", dest_ip_str, dest_port);

    int send_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    int icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    // DUAL-SOCKET INTEGRATION: Spin up a raw listener catching native TCP frames
    int tcp_sock  = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    if (send_sock < 0 || icmp_sock < 0 || tcp_sock < 0) {
        perror("[-] Raw Socket Generation Failed (Execute using sudo)");
        return;
    }

    int one = 1;
    if (setsockopt(send_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("[-] Failed setting IP_HDRINCL");
        return;
    }

    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(dest_port);
    dest_addr.sin_addr = dest_addr_struct;

    char packet[PACKET_SIZE];
    char rcv_buffer[1024];

    printf("Hop #\tHop Gateway IP\t\tStatus / Response\n");
    printf("-----------------------------------------------------------------\n");

    for (int ttl = 1; ttl <= MAX_HOPS; ttl++) {
        memset(packet, 0, PACKET_SIZE);

        #if defined(__APPLE__) || defined(__MACH__)
            struct ip *ip_hdr = (struct ip *)packet;
            struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + sizeof(struct ip));
        #else
            struct iphdr *ip_hdr = (struct iphdr *)packet;
            struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + sizeof(struct iphdr));
        #endif

        #if defined(__APPLE__) || defined(__MACH__)
            ip_hdr->ip_hl = 5;
            ip_hdr->ip_v = 4;
            ip_hdr->ip_tos = 0;
            ip_hdr->ip_len = PACKET_SIZE; 
            ip_hdr->ip_id = htons(54321 + ttl);
            ip_hdr->ip_off = 0;
            ip_hdr->ip_ttl = ttl; 
            ip_hdr->ip_p = IPPROTO_TCP;
            ip_hdr->ip_src.s_addr = local_ip;
            ip_hdr->ip_dst = dest_addr.sin_addr;
        #else
            ip_hdr->ihl = 5;
            ip_hdr->version = 4;
            ip_hdr->tos = 0;
            ip_hdr->tot_len = htons(PACKET_SIZE);
            ip_hdr->id = htons(54321 + ttl);
            ip_hdr->frag_off = 0;
            ip_hdr->ttl = ttl;
            ip_hdr->protocol = IPPROTO_TCP;
            ip_hdr->saddr = local_ip; 
            ip_hdr->daddr = dest_addr.sin_addr.s_addr;
        #endif

        // Unique dynamic source ports per hop so we can isolate replies safely
        // uint16_t current_src_port = 45678 + ttl;
        //
        // Fix: Remove "+ ttl" to stop triggering port-scan defense mechanics
        uint16_t current_src_port = 45678;

        #if defined(__APPLE__) || defined(__MACH__)
            tcp_hdr->th_sport = htons(current_src_port); 
            tcp_hdr->th_dport = htons(dest_port); 
            tcp_hdr->th_seq = htonl(1);
            tcp_hdr->th_ack = 0;
            tcp_hdr->th_off = 5; 
            tcp_hdr->th_flags = TH_SYN; 
            tcp_hdr->th_win = htons(65535);
            tcp_hdr->th_sum = 0;
            tcp_hdr->th_urp = 0;
        #else
            tcp_hdr->source = htons(current_src_port);
            tcp_hdr->dest = htons(dest_port);
            tcp_hdr->seq = htonl(1);
            tcp_hdr->ack_seq = 0;
            tcp_hdr->doff = 5;
            tcp_hdr->syn = 1; 
            tcp_hdr->window = htons(65535);
            tcp_hdr->check = 0;
            tcp_hdr->urg_ptr = 0;
        #endif

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

        sendto(send_sock, packet, PACKET_SIZE, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

        // Use select() to multiplex listening onto BOTH sockets concurrently
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(icmp_sock, &read_fds);
        FD_SET(tcp_sock, &read_fds);

        struct timeval timeout;
        timeout.tv_sec = TIMEOUT_SEC;
        timeout.tv_usec = 0;

        int max_fd = (icmp_sock > tcp_sock) ? icmp_sock : tcp_sock;
        int activity = select(max_fd + 1, &read_fds, NULL, NULL, &timeout);

        if (activity <= 0) {
            printf("%d\t*\t\t\t[Request Timed Out / Dropped]\n", ttl);
            continue;
        }

        struct sockaddr_in from_addr;
        socklen_t from_len = sizeof(from_addr);
        memset(rcv_buffer, 0, sizeof(rcv_buffer));
        char ip_res[INET_ADDRSTRLEN];

        // PATH A: ICMP intermediate router node triggered
        if (FD_ISSET(icmp_sock, &read_fds)) {
            if (recvfrom(icmp_sock, rcv_buffer, sizeof(rcv_buffer), 0, (struct sockaddr *)&from_addr, &from_len) > 0) {
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

                inet_ntop(AF_INET, &(from_addr.sin_addr), ip_res, INET_ADDRSTRLEN);

                if (icmp_reply_hdr->icmp_type == ICMP_TIMXCEED) {
                    printf("%d\t%s\t\tTransit Hop Verified (TCP SYN Intercept)\n", ttl, ip_res);
                } else {
                    printf("%d\t%s\t\tICMP Feedback Encountered (Type: %d)\n", ttl, ip_res, icmp_reply_hdr->icmp_type);
                }
            }
        }
        // PATH B: Destination Node Native TCP Handshake intercepted!
        else if (FD_ISSET(tcp_sock, &read_fds)) {
            if (recvfrom(tcp_sock, rcv_buffer, sizeof(rcv_buffer), 0, (struct sockaddr *)&from_addr, &from_len) > 0) {
                int ip_hdr_len = 0;
                struct tcphdr *rcv_tcp_hdr = NULL;

                #if defined(__APPLE__) || defined(__MACH__)
                    struct ip *ip_reply_hdr = (struct ip *)rcv_buffer;
                    ip_hdr_len = ip_reply_hdr->ip_hl * 4;
                    rcv_tcp_hdr = (struct tcphdr *)(rcv_buffer + ip_hdr_len);
                #else
                    struct iphdr *ip_reply_hdr = (struct iphdr *)rcv_buffer;
                    ip_hdr_len = ip_reply_hdr->ihl * 4;
                    rcv_tcp_hdr = (struct tcphdr *)(rcv_buffer + ip_hdr_len);
                #endif

                inet_ntop(AF_INET, &(from_addr.sin_addr), ip_res, INET_ADDRSTRLEN);

                uint16_t check_dport = 0;
                uint8_t flags = 0;

                // Explicit compilation separation of Layer 4 TCP flag definitions
                #if defined(__APPLE__) || defined(__MACH__)
                    check_dport = ntohs(rcv_tcp_hdr->th_dport);
                    flags = rcv_tcp_hdr->th_flags;
                #else
                    // Linux Standard Header Mapping (dest and syn/ack fields)
                    check_dport = ntohs(rcv_tcp_hdr->dest);

                    // Fallback evaluation if standard struct bitfields vary across Linux flavors
                    #if defined(__FAVOR_BSD)
                        flags = rcv_tcp_hdr->th_flags;
                    #else
                        // Directly access the 13th byte of the TCP header containing the 
                        // 8-bit flags field
                        flags = *((uint8_t *)rcv_tcp_hdr + 13);
                    #endif
                #endif

                if (check_dport == current_src_port && strcmp(ip_res, dest_ip_str) == 0) {
                    // Check for SYN-ACK (0x12) or RST (0x04 / 0x14) flag values
                    if ((flags & 0x02) && (flags & 0x10)) { // SYN (0x02) + ACK (0x10)
                        printf("%d\t%s\t\t[Port Open / Final Target Reached via SYN-ACK]\n", 
                                ttl, ip_res);
                    } else if (flags & 0x04) { // RST (0x04)
                        printf("%d\t%s\t\t[Port Closed / Final Target Reached via RST-ACK]\n", 
                                ttl, ip_res);
                    } else {
                        printf("%d\t%s\t\t[Target Reached via General TCP Packet (Flags: 0x%02x)]\n", 
                                ttl, ip_res, flags);
                    }
                    break;
                } else {
                    // Ignored ambient thread network payload; 
                    // roll back sequence step to retry current hop
                    ttl--;
                }
            }
        }
    }
    close(send_sock);
    close(icmp_sock);
    close(tcp_sock);
}

int main(int argc, char *argv[]) {
    // Verify both parameters are provided (index 1 = domain, index 2 = port)
    if (argc < 3) {
        printf("Usage: sudo %s <Destination Domain/IP> <Target Port>\n", argv[0]);
        return 1;
    }

    uint32_t local_ip = get_local_ip_address();
    if (local_ip == 0) {
        return 1;
    }

    // FIX: Pass the first command argument (domain name string)
    struct in_addr dest_addr_struct;
    if (resolve_hostname(argv[1], &dest_addr_struct) < 0) {
        return 1;
    }

    char resolved_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &dest_addr_struct, resolved_ip_str, INET_ADDRSTRLEN);

    // FIX: Extract the second command argument (port integer)
    int target_port = atoi(argv[2]);

    run_l4_tcp_traceroute(dest_addr_struct, resolved_ip_str, target_port, local_ip);

    return 0;
}
