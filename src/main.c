#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/capture.h"

#define MAX_DEVICES 32

int main() {
    pcap_if_t *alldevs, *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    char* device_names[MAX_DEVICES];
    int device_count = 0;

    // Loading all devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 1;
    }

    printf("📡 Available Network Devices:\n");

    // Indexing all devices
    for (dev = alldevs; dev != NULL && device_count < MAX_DEVICES; dev = dev->next) {
        printf("  [%d] %s", device_count + 1, dev->name);
        if (dev->description) {
            printf(" – %s", dev->description);
        }
        printf("\n");

        // Saving device paths
        device_names[device_count] = strdup(dev->name); // Reserve the memory for the device
        device_count++;
    }

    if (device_count == 0) {
        printf("❌ No network interfaces found.\n");
        pcap_freealldevs(alldevs);
        return 1;
    }

    // Recieving users choice
    int choice = 0;
    printf("\nEnter the number of the interface to use: ");
    scanf("%d", &choice);

    while (choice < 1 || choice > device_count) {
        printf("❌ Invalid choice.\n");
        printf("\nEnter the number of the interface to use: ");
        scanf("%d", &choice);
    }

    // Start capture
    printf("\n✅ Starting capture on device: %s\n\n", device_names[choice - 1]);
    start_capture(device_names[choice - 1]);

    // Clean-up
    for (int i = 0; i < device_count; i++) {
        free(device_names[i]);
    }
    pcap_freealldevs(alldevs);

    return 0;
}
