#include <stdio.h>
#include <stdint.h>


const char* get_protocol_name(uint8_t proto_num) {
    switch (proto_num) {
        case 1:  return "ICMP";       // Internet Control Message Protocol
        case 2:  return "IGMP";       // Internet Group Management Protocol
        case 6:  return "TCP";        // Transmission Control Protocol
        case 17: return "UDP";        // User Datagram Protocol
        case 41: return "IPv6";       // IPv6 encapsulation
        case 43: return "Routing";    // Routing Header for IPv6
        case 44: return "Fragment";   // Fragment Header for IPv6
        case 47: return "GRE";        // Generic Routing Encapsulation
        case 50: return "ESP";        // Encapsulating Security Payload
        case 51: return "AH";         // Authentication Header
        case 58: return "ICMPv6";     // ICMP for IPv6
        case 89: return "OSPF";       // Open Shortest Path First
        case 132: return "SCTP";      // Stream Control Transmission Protocol
        default: return "Unknown";
    }
}

void print_mac(const uint8_t* mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}
