#ifndef PARSER_H
#define PARSER_H

#include <pcap.h>

void parse_ethernet_layer(const u_char* packet, int length);

#endif
