#ifndef PARSER_H
#define PARSER_H

#include <stdint.h>
#include <pcap.h>
#include "analyzer.h"

uint16_t parse_ethernet_layer(const u_char* packet, int length);
uint8_t parse_ipv4_layer(const u_char* packet, int length, packet_summary_t* summary);
uint8_t parse_ipv6_layer(const u_char* packet, int length, packet_summary_t* summary);
void parse_arp_layer(const u_char* packet, int length, packet_summary_t* summary);

#endif
