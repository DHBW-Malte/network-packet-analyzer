#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include "../include/capture.h"
#include "../include/parser.h"
#include "../include/analyzer.h"

#define MAX_PACKETS 1000

static packet_summary_t summaries[MAX_PACKETS];
static struct packet_stats stats;
static int packet_index = 0;
static int capture_limit = 0;

// Function to handle each packet
static void packet_handler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
    if (packet_index >= capture_limit) return;
    (void)user;
    // Parsing the ethertype
    uint16_t ethertype = parse_ethernet_layer(packet, header->len);
    uint8_t protocol = 0;

    // Function to parse the second layer based on the ethertype
    if (ethertype == 0x0800) {
        protocol = parse_ipv4_layer(packet, header->len, &summaries[packet_index]);
    } else if (ethertype == 0x86DD) {
        protocol = parse_ipv6_layer(packet, header->len, &summaries[packet_index]);
    } else if (ethertype == 0x0806) {
        parse_arp_layer(packet, header->len, &summaries[packet_index]);
    }
    
    // Function to update the stats for the analyzer
    update_stats(&stats, ethertype, protocol, header->len);
    packet_index++;

    printf("\n");

}

// Function to start the packet capturing on the selected device
void start_capture(const char* device_name, int max_packets) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;

    packet_index = 0;
    capture_limit = max_packets;

    handle = pcap_open_live(device_name, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "❌ Couldn't open device %s: %s\n", device_name, errbuf);
        return;
    }
    
    // Starting the capturing loop on the selected device (until number of captured packets reached)
    pcap_loop(handle, max_packets, packet_handler, NULL);

    pcap_close(handle);
    print_stats(&stats);
}
