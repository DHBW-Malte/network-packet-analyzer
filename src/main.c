#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/capture.h"

#define DEFAULT_PACKETS 10
#define MAX_PACKETS 1000

static int max_packets = DEFAULT_PACKETS;

// Function to start the cli tool (listing available devices and )
void list_devices_and_capture() {
    // Variables to store the network devices and error messages
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // Error handling if libpcap failed to find network devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "❌ Error finding devices: %s\n", errbuf);
        exit(1);
    }
    
    // Listing all founded network device with index
    printf("📡 Available Network Devices:\n");
    int i = 0;
    for (pcap_if_t* d = alldevs; d != NULL; d = d->next) {
        printf("  [%d] %s", ++i, d->name);
        if (d->description) printf(" – %s", d->description);
        printf("\n");
    }

    // Variables for handling the device selection
    int choice = -1;
    pcap_if_t* chosen = NULL;

    // Counting available devices
    int total_devices = 0;
    for (pcap_if_t* d = alldevs; d != NULL; d = d->next) {
        total_devices++;
    }

    // Loop to ensure valid user input for the device selection
    while (1) {
        printf("\nEnter the number of the interface to use (1-%d): ", total_devices);

        if (scanf("%d", &choice) != 1) {
            fprintf(stderr, "❌ Invalid input. Please enter a number.\n");
            // Input buffer cleaning after invalid input
            while (getchar() != '\n');
            continue;
        }

        if (choice < 1 || choice > total_devices) {
            fprintf(stderr, "❌ Invalid selection. Please choose a number between 1 and %d.\n", total_devices);
            continue;
        }

        break;
    }

    // Select the choosen device from the device list
    chosen = alldevs;
    for (int j = 1; j < choice; j++) {
        chosen = chosen->next;
    }
    
    // Starting with the capturing, parsing and analyzing
    printf("\n✅ Starting capture on device: %s\n\n", chosen->name);

    start_capture(chosen->name, max_packets);
    pcap_freealldevs(alldevs);
}

// Entry-point for the analyzer
int main(int argc, char* argv[]) {
    if (argc > 1) {
        // Help view for the cli tool
        if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
            printf("📡  Network Packet Analyzer\n\n");
            printf("Usage:\n");
            printf("  %s -c <packet_count>      Capture a fixed number of packets (default: %d)\n", argv[0], DEFAULT_PACKETS);
            printf("  %s -h | --help            Show this help message\n\n", argv[0]);
            printf("Note:\n");
            printf("  Requires root privileges for capturing.\n");
            return 0;
        }
        // Handling the -c option to set the amount of packets (default 10)
        if (strcmp(argv[1], "-c") == 0 && argc == 3) {
            max_packets = atoi(argv[2]);
            if (max_packets <= 0 || max_packets > MAX_PACKETS) {
                fprintf(stderr, "❌ Invalid packet count. Must be between 1 and %d\n", MAX_PACKETS);
                return 1;
            }
        // Handling invalid arguments
        } else {
            fprintf(stderr, "❌ Invalid arguments.\n");
            fprintf(stderr, "Use '%s -h' for help.\n", argv[0]);
            return 1;
        }
    } else {
        printf("ℹ️ No packet count specified. Defaulting to %d packets...\n\n", DEFAULT_PACKETS);
    }
    // Starting the CLI tool
    list_devices_and_capture();
    return 0;
}
