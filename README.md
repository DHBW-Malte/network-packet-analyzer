# System Programming – Network Packet Analyzer

**Author**: Malte Opderbeck  
**Semester**: 4th  
**Course**: System Programming  
**Lecturer**: Fabian Zaremba

---

## Description

A lightweight, modular **network packet analyzer** written in **C** for Linux systems. 
It captures, parses, and analyzes raw network traffic in real time using **`libpcap`**.

---

## Features

- **Live packet capture** on a user-selected network interface
- **Protocol dissection**:
  - Ethernet
  - IPv4 & IPv6
  - TCP, UDP, ICMP, ICMPv6
  - ARP
- **Summary analysis**:
  - Total packets
  - Average packet size
  - Protocol distribution

---

## Build & Run

### Prerequisites

- **GCC**
- **libpcap** development headers

Install on Ubuntu:

```bash
sudo apt install libpcap-dev
```

### Build

```bash
make
```

### Run

```bash
sudo ./netanalyzer -c <packet_count>
```

> **Note:** Root permissions are required to access network interfaces.

Example:

```bash
sudo ./netanalyzer -c 15
```

---

## Project Structure

```text
include/
├── analyzer.h    # Analysis interface and summary struct
├── parser.h      # Protocol-level parsing functions
├── utils.h       # Helper functions (e.g. MAC printer)

src/
├── main.c        # Entry point and interface selection
├── parser.c      # Protocol parsing (Ethernet, IPv4, IPv6, ARP)
├── analyzer.c    # Statistics and protocol summary
├── utils.c       # Helper utilities
```

---

