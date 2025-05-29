#ifndef PARSER_H
#define PARSER_H

#include <stdint.h>
#include <pcap.h>

uint16_t parse_ethernet_layer(const u_char* packet, int length);
void parse_ipv4_layer(const u_char* packet, int length);
void parse_ipv6_layer(const u_char* packet, int length);
void parse_arp_layer(const u_char* packet, int length);

#endif
