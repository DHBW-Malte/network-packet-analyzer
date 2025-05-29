#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include "../include/capture.h"
#include "../include/parser.h"

// Function to print out the length of each captured packet
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // Printing second network layer
    uint16_t ethertype = parse_ethernet_layer(packet, header->len);
    // Printing third network layer
    if (ethertype == 0x0800) { // Parsing if type is IPv4
        parse_ipv4_layer(packet, header->len);
    }
    if (ethertype == 0x86DD) { // Parsing if type is IPv6
        parse_ipv6_layer(packet, header->len);
    }
}

// Function to capture packets of the selected interface
void start_capture(const char* interface, int packet_count) {
    char errbuf[PCAP_ERRBUF_SIZE];

    // Open the network interface for live packet capture
    // Buffer size for user-space-buffer (BUFSIZE) to store raw packets data
    // Promiscouse mode enabled (1) recieviing every traffic on the interface
    // 1 sec Timeout (1000) to return the buffer content even if the buffer is not full
    pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", interface, errbuf);
        return;
    }
    // Start of the loop to capture the packets
    pcap_loop(handle, packet_count, packet_handler, NULL); // capture 10 packets
    pcap_close(handle);
}
