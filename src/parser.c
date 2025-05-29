#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "../include/parser.h"
#include "../include/utils.h"
#include <string.h>

struct ethernet_header {
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint16_t ethertype;
};

struct ipv4_header {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dest_ip;
};

struct ipv6_header {
    uint32_t version_tc_fl;
    uint16_t payload_length;
    uint8_t next_header;
    uint8_t hop_limit;
    struct in6_addr src_ip;
    struct in6_addr dest_ip;
};

struct arp_header {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t oper;
    uint8_t sender_mac[6];
    uint32_t sender_ip;
    uint8_t target_mac[6];
    uint32_t target_ip;
};

// Function to parse the Ethernet header (first 14 bytes of the packet)
uint16_t parse_ethernet_layer(const u_char* packet, int length) {
    if (length < 14) {
        printf("❌ Packet too short for Ethernet header.\n");
        return 0;
    }

    const struct ethernet_header* eth = (const struct ethernet_header*) packet;
    uint16_t ethertype = ntohs(eth->ethertype);  // Using ntohs to ensure the correct reading order

    printf("[Ethernet] ");
    print_mac(eth->src_mac);
    printf(" → ");
    print_mac(eth->dest_mac);
    printf(" | Type: ");

    switch (ethertype) {
        case 0x0800: printf("IPv4"); break;
        case 0x86DD: printf("IPv6"); break;
        case 0x0806: printf("ARP"); break;
        default:     printf("0x%04x", ethertype); break;
    }

    printf("\n");

    return ethertype;
}

// Function to parse the IPv4 layer header
uint8_t parse_ipv4_layer(const u_char* packet, int length, packet_summary_t* summary) {
    if (length < 14 + 20) {
        printf("  └─ ❌ Packet too short for IPv4 header.\n");
        return 0;
    }

    // IPv4-Header starts after 14 bytes (after ethernet header)
    const struct ipv4_header* ip = (const struct ipv4_header*) (packet + 14);

    uint8_t version = ip->version_ihl >> 4;         // Version are the upper 4 bits
    uint8_t ihl = ip->version_ihl & 0x0F;           // IHL (Internet Header Length) are the lower 4 bits
    uint16_t total_length = ntohs(ip->total_length); // Using ntohs to ensure the correct reading order
    uint8_t protocol = ip->protocol;

    char src_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip->src_ip), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip->dest_ip), dest_ip, INET_ADDRSTRLEN);

    printf("  └─ [IPv4] Version: %d | IHL: %d (×4 = %d bytes) | Length: %d | Protocol: %s\n",
           version, ihl, ihl * 4, total_length, get_protocol_name(protocol));
    printf("     └─ Src IP: %s\n", src_ip);
    printf("     └─ Dst IP: %s\n", dest_ip);

    summary->protocol = protocol;
    strncpy(summary->src_ip, src_ip, INET6_ADDRSTRLEN);
    strncpy(summary->dst_ip, dest_ip, INET6_ADDRSTRLEN);

    return protocol;
}

// Function to parse the IPv6 layer header
uint8_t parse_ipv6_layer(const u_char* packet, int length, packet_summary_t* summary) {
    if (length < 14 + 40) {
        printf("  └─ ❌ Packet too short for IPv6 header.\n");
        return 0;
    }

    const u_char* ip_start = packet + 14;

    // First 4 bytes: Version (4), Traffic Class (8), Flow Label (20)
    uint32_t version_tc_fl = ntohl(*(uint32_t*)ip_start);
    uint8_t version = (version_tc_fl >> 28) & 0x0F;

    uint16_t payload_length = ntohs(*(uint16_t*)(ip_start + 4));
    uint8_t next_header = *(ip_start + 6);
    uint8_t hop_limit = *(ip_start + 7);

    char src_ip[INET6_ADDRSTRLEN];
    char dest_ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, ip_start + 8, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET6, ip_start + 24, dest_ip, sizeof(dest_ip));

    printf("  └─ [IPv6] Version: %d | Payload Length: %d | Next Header: %s | Hop Limit: %d\n",
           version, payload_length, get_protocol_name(next_header), hop_limit);
    printf("     └─ Src IP: %s\n", src_ip);
    printf("     └─ Dst IP: %s\n", dest_ip);

    summary->protocol = next_header;
    strncpy(summary->src_ip, src_ip, INET6_ADDRSTRLEN);
    strncpy(summary->dst_ip, dest_ip, INET6_ADDRSTRLEN);

    return next_header;
}

void parse_arp_layer(const u_char* packet, int length, packet_summary_t* summary) {
    if ((size_t)length < 14 + sizeof(struct arp_header)) {
        printf("  └─ ❌ Packet too short for ARP header.\n");
        return;
    }

    const struct arp_header* arp = (const struct arp_header*)(packet + 14);

    char sender_ip[INET_ADDRSTRLEN];
    char target_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(arp->sender_ip), sender_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(arp->target_ip), target_ip, INET_ADDRSTRLEN);

    printf("  └─ [ARP] Operation: %s\n", (ntohs(arp->oper) == 1) ? "Request" :
                                           (ntohs(arp->oper) == 2) ? "Reply" : "Unknown");
    printf("     └─ Sender MAC: ");
    print_mac(arp->sender_mac);
    printf(" | Sender IP: %s\n", sender_ip);
    printf("     └─ Target MAC: ");
    print_mac(arp->target_mac);
    printf(" | Target IP: %s\n", target_ip);

    summary->protocol = 0;  // No protocol for ARP
    strncpy(summary->src_ip, sender_ip, INET6_ADDRSTRLEN);
    strncpy(summary->dst_ip, target_ip, INET6_ADDRSTRLEN);
}
