#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include "../include/parser.h"

struct ethernet_header {
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint16_t ethertype;
};

// Helper function to print MAC address in readable format
void print_mac(const u_char* mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// Function to parse the Ethernet header (first 14 bytes of the packet)
void parse_ethernet_layer(const u_char* packet, int length) {
    if (length < 14) {
        printf("❌ Packet too short for Ethernet header.\n");
        return;
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
}
