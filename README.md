# Network Packet Sniffer

A comprehensive network packet sniffer written in C++ using libpcap for packet capture and analysis.

## Features

- **Real-time packet capture** from network interfaces
- **Protocol analysis** for Ethernet, IP, TCP, UDP, ICMP
- **Flexible filtering** using Berkeley Packet Filter (BPF) expressions
- **Detailed packet information** including headers and payload
- **Statistics tracking** with protocol breakdown
- **Cross-platform support** (Linux, macOS, BSD)
- **Command-line interface** with comprehensive options

## Prerequisites

### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install libpcap-dev build-essential
```

### CentOS/RHEL/Fedora
```bash
sudo yum install libpcap-devel gcc-c++
# or on newer versions:
sudo dnf install libpcap-devel gcc-c++
```

### macOS
```bash
# Using Homebrew
brew install libpcap

# Using MacPorts
sudo port install libpcap
```

## Building

```bash
# Clone the repository
git clone <repository-url>
cd jvkec-network-packet-sniffer

# Install dependencies (Ubuntu/Debian)
make install-deps

# Build the project
make

# Build with debug information
make debug

# Run tests
make test
```

## Usage

**Note: Root privileges are required for packet capture.**

### Basic Usage
```bash
# Capture on default interface
sudo ./bin/sniffer

# Capture on specific interface
sudo ./bin/sniffer -i eth0

# List available interfaces
sudo ./bin/sniffer -l
```

### Advanced Usage
```bash
# Capture with BPF filter
sudo ./bin/sniffer -i eth0 -f "tcp port 80"

# Capture limited number of packets
sudo ./bin/sniffer -i eth0 -c 100

# Enable promiscuous mode
sudo ./bin/sniffer -i eth0 -p

# Capture HTTPS traffic
sudo ./bin/sniffer -i any -f "tcp port 443"

# Capture DNS queries
sudo ./bin/sniffer -i any -f "udp port 53"
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `-i, --interface` | Network interface to capture on |
| `-f, --filter` | BPF filter expression |
| `-c, --count` | Number of packets to capture (0 = unlimited) |
| `-s, --snaplen` | Snapshot length (default: 65535) |
| `-p, --promiscuous` | Enable promiscuous mode |
| `-l, --list` | List available network interfaces |
| `-h, --help` | Show help message |

## BPF Filter Examples

```bash
# TCP traffic only
"tcp"

# HTTP traffic
"tcp port 80"

# Traffic to/from specific IP
"host 192.168.1.1"

# Traffic from specific network
"src net 192.168.1.0/24"

# Combined filters
"tcp and (port 80 or port 443)"
```

## Architecture

```
├── include/          # Header files
│   ├── packet_parser.hpp  # Packet parsing and analysis
│   ├── sniffer.hpp        # Main packet capture logic
│   └── utils.hpp          # Utility functions
├── src/              # Source files
│   ├── main.cpp           # Application entry point
│   ├── packet_parser.cpp  # Packet parsing implementation  
│   ├── sniffer.cpp        # Packet capture implementation
│   └── utils.cpp          # Utility functions implementation
└── test/             # Test files
    └── packet_parser_test.cpp  # Unit tests
```

## Key Classes

### Sniffer
- Manages packet capture using libpcap
- Handles device selection and filtering
- Provides callback mechanism for packet processing

### PacketParser  
- Parses network protocol headers (Ethernet, IP, TCP, UDP)
- Extracts and displays packet information
- Maintains capture statistics

### Utils
- Provides utility functions for string manipulation
- Network address validation and conversion
- Timestamp formatting and display helpers

## Sample Output

```
[INFO] Starting packet capture...
[INFO] Device: eth0
[INFO] Filter: tcp port 80
[INFO] Packet count: unlimited (press Ctrl+C to stop)
==================================================

=== Packet Captured ===
Timestamp: 2024-01-15 14:30:45.123456
Captured length: 74 bytes
Original length: 74 bytes
Ethernet Header:
  Source MAC: aa:bb:cc:dd:ee:ff
  Dest MAC: 11:22:33:44:55:66
  EtherType: 0x800 (IPv4)
IP Header:
  Version: 4
  Header Length: 20 bytes
  Total Length: 60 bytes
  Protocol: 6 (TCP)
  TTL: 64
  Source IP: 192.168.1.100
  Dest IP: 93.184.216.34
TCP Header:
  Source Port: 54321
  Dest Port: 80
  Sequence Number: 1234567890
  Ack Number: 987654321
  Flags: SYN ACK 
  Window Size: 65535
  Application: HTTP
```

## Testing

```bash
# Run unit tests
make test

# Clean build artifacts
make clean
```

## Security Considerations

- **Root privileges required**: Packet capture requires administrative access
- **Network monitoring**: Be aware of privacy and legal implications
- **Promiscuous mode**: Can capture all network traffic on the segment
- **Filter carefully**: Use specific filters to avoid capturing sensitive data

## Troubleshooting

### Permission Denied
```bash
# Ensure you're running with sudo
sudo ./bin/sniffer

# Or set capabilities (Linux only)
sudo setcap cap_net_raw+ep ./bin/sniffer
```

### No Suitable Device Found
```bash
# List available interfaces
sudo ./bin/sniffer -l

# Try using 'any' interface
sudo ./bin/sniffer -i any
```

### Compilation Issues
```bash
# Ensure libpcap development headers are installed
sudo apt-get install libpcap-dev

# Check compiler version (requires C++14)
g++ --version
```

## License

MIT