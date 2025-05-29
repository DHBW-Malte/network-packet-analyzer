#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <stdint.h>

const char* get_protocol_name(uint8_t proto_num);
void print_mac(const uint8_t* mac);

#endif
