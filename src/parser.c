#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include "../include/parser.h"
#include "../include/utils.h"

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
void parse_ipv4_layer(const u_char* packet, int length) {
    if (length < 14 + 20) {
        printf("  └─ ❌ Packet too short for IPv4 header.\n");
        return;
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
}
