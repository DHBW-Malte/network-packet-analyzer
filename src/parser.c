#include <stdio.h>
#include <stdint.h>
#include "../include/parser.h"

// Helper function to print MAC address in readable format
void print_mac(const u_char* mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// Function to parse the Ethernet header (first 14 bytes of the packet)
void parse_ethernet_header(const u_char* packet, int length) {
    if (length < 14) {
        printf("Packet too short for Ethernet header.\n");
        return;
    }

    const u_char* dest_mac = packet;
    const u_char* src_mac = packet + 6;
    uint16_t ethertype = (packet[12] << 8) | packet[13];

    printf("[Ethernet] ");
    print_mac(src_mac);
    printf(" → ");
    print_mac(dest_mac);
    printf(" | Type: ");

    switch (ethertype) {
        case 0x0800: printf("IPv4"); break;
        case 0x86DD: printf("IPv6"); break;
        case 0x0806: printf("ARP"); break;
        default:     printf("0x%04x", ethertype); break;
    }

    printf("\n");
}
