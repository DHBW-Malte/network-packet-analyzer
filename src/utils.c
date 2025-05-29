#include <stdio.h>
#include <stdint.h>

const char* get_protocol_name(uint8_t proto_num) {
    switch (proto_num) {
        case 1:  return "ICMP";
        case 6:  return "TCP";
        case 17: return "UDP";
        default: return "Unknown";
    }
}

void print_mac(const uint8_t* mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}
