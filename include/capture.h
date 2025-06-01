#ifndef CAPTURE_H
#define CAPTURE_H

#include <pcap.h>

void start_capture(const char* device_name, int max_packets);

#endif


