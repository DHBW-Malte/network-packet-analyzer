#ifndef ANALYZER_H
#define ANALYZER_H

#include <stdint.h>
#include <netinet/in.h>

typedef struct {
    uint8_t protocol;
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
} packet_summary_t;

struct packet_stats {
    int total_packets;
    int total_packet_length;

    int ipv4_count;
    int ipv6_count;
    int arp_count;
    int other_count;

    int tcp_count;
    int udp_count;
    int icmp_count;
    int other_transport_count;
};

void init_stats(struct packet_stats* stats);
void update_stats(struct packet_stats* stats, uint16_t ethertype, uint8_t protocol, int packet_length);
void print_stats(const struct packet_stats* stats);

void run_analysis(packet_summary_t* summaries, int count);

#endif
