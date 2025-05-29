#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/parser.h"
#include "../include/analyzer.h"


#define MAX_PACKETS 1000

static int packet_count = 0;
static int max_packets = MAX_PACKETS;
static packet_summary_t summaries[MAX_PACKETS];
static struct packet_stats stats;

void handle_packet(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
    if (packet_count >= max_packets) return;

    uint16_t ethertype = parse_ethernet_layer(packet, header->len);
    
    uint8_t protocol = 0;

    if (ethertype == 0x0800) {
        protocol = parse_ipv4_layer(packet, header->len, &summaries[packet_count]);
    } else if (ethertype == 0x86DD) {
        protocol = parse_ipv6_layer(packet, header->len, &summaries[packet_count]);
    } else if (ethertype == 0x0806) {
        parse_arp_layer(packet, header->len, &summaries[packet_count]);
    }

    update_stats(&stats, ethertype, protocol, header->len);

    (void)user;
    packet_count++;
}

void list_devices_and_capture() {
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "❌ Error finding devices: %s\n", errbuf);
        exit(1);
    }

    printf("📡 Available Network Devices:\n");
    int i = 0;
    for (pcap_if_t* d = alldevs; d != NULL; d = d->next) {
        printf("  [%d] %s", ++i, d->name);
        if (d->description) printf(" – %s", d->description);
        printf("\n");
    }

    printf("\nEnter the number of the interface to use: ");
    int choice;
    scanf("%d", &choice);

    pcap_if_t* chosen = alldevs;
    for (int j = 1; j < choice && chosen != NULL; j++) {
        chosen = chosen->next;
    }

    if (!chosen) {
        fprintf(stderr, "❌ Invalid interface selection.\n");
        pcap_freealldevs(alldevs);
        exit(1);
    }

    printf("\n✅ Starting capture on device: %s\n\n", chosen->name);

    pcap_t* handle = pcap_open_live(chosen->name, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "❌ Couldn't open device %s: %s\n", chosen->name, errbuf);
        pcap_freealldevs(alldevs);
        exit(1);
    }

    pcap_loop(handle, max_packets, handle_packet, NULL);

    pcap_close(handle);
    pcap_freealldevs(alldevs);
}

int main(int argc, char* argv[]) {
    if (argc == 3 && strcmp(argv[1], "-c") == 0) {
        max_packets = atoi(argv[2]);
        if (max_packets <= 0 || max_packets > MAX_PACKETS) {
            fprintf(stderr, "❌ Invalid packet count. Must be between 1 and %d\n", MAX_PACKETS);
            return 1;
        }
    } else {
        printf("ℹ️ Usage: %s -c <packet_count>\n", argv[0]);
        printf("   Defaulting to %d packets...\n\n", max_packets);
    }

    list_devices_and_capture();
    print_stats(&stats);

    return 0;
}
