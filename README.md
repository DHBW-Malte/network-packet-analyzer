# System Programming – Network Packet Analyzer

**Author**: Malte Opderbeck  
**Semester**: 4th  
**Lecture**: System Programming  
**Lecturer**: Fabian Zaremba

---

## Description

A lightweight network packet analyzer written in C for Linux systems.
It captures, parses, and analyzes raw network traffic in real time.

## Features

- Live packet capture on a selected network interface
- Protocol-level dissection (Ethernet, IPv4, TCP, UDP, ICMP, ARP)
- Port and IP address tracking
- Lightweight command-line output

## Build & Run

### Prerequisites

- GCC
- `libpcap` development headers

### Build

```bash
make
```

### Run

```bash
sudo ./netanalyzer
```

Root permissions are required to access network interfaces directly.
