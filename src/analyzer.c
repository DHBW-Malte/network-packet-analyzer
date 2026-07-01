#include <stdio.h>
#include <string.h>
#include "../include/analyzer.h"

// Init for the values of the analyzer
void init_stats(struct packet_stats* stats) {
    stats->total_packets = 0;
    stats->total_packet_length = 0;

    stats->ipv4_count = 0;
    stats->ipv6_count = 0;
    stats->arp_count = 0;
    stats->other_count = 0;

    stats->tcp_count = 0;
    stats->udp_count = 0;
    stats->icmp_count = 0;
    stats->other_transport_count = 0;
}

// Function to update the stats from the analyzer after each packet
void update_stats(struct packet_stats* stats, uint16_t ethertype, uint8_t protocol, int packet_length) {
    stats->total_packets++;
    stats->total_packet_length += packet_length;

    switch (ethertype) {
        case 0x0800: // IPv4
            stats->ipv4_count++;
            switch (protocol) {
                case 6:  stats->tcp_count++; break;
                case 17: stats->udp_count++; break;
                case 1:  stats->icmp_count++; break;
                default: stats->other_transport_count++; break;
            }
            break;
        case 0x86DD: // IPv6
            stats->ipv6_count++;
            break;
        case 0x0806: // ARP
            stats->arp_count++;
            break;
        default:
            stats->other_count++;
            break;
    }
}

// Function to print the analyze
void print_stats(const struct packet_stats* stats) {
    printf("\n📊 Packet Summary:\n");
    printf("  Total packets: %d\n", stats->total_packets);
    printf("  Average packet size: %.2f bytes\n",
           stats->total_packets > 0 ? (float)stats->total_packet_length / stats->total_packets : 0);

    printf("\n🔎 Ethernet Type Breakdown:\n");
    printf("  IPv4:  %d\n", stats->ipv4_count);
    printf("  IPv6:  %d\n", stats->ipv6_count);
    printf("  ARP:   %d\n", stats->arp_count);
    printf("  Other: %d\n", stats->other_count);

    printf("\n🧪 IPv4 Transport Protocols:\n");
    printf("  TCP:   %d\n", stats->tcp_count);
    printf("  UDP:   %d\n", stats->udp_count);
    printf("  ICMP:  %d\n", stats->icmp_count);
    printf("  Other: %d\n", stats->other_transport_count);
}

