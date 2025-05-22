# Network Packet Sniffer

A command-line network packet analyzer written in Rust that captures and displays network traffic in real-time with detailed protocol parsing.

## Features

- 🔍 **Real-time packet capture** from network interfaces
- 🌐 **Multi-protocol support** including Ethernet, IPv4, TCP, and UDP
- 📊 **Detailed packet analysis** with protocol-specific information
- 🎯 **MAC address parsing** with manufacturer identification
- 🔗 **Port service identification** for common protocols
- 📋 **Clean, structured output** with emojis for easy readability

## Prerequisites

- Rust (latest stable version)

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/Soroushsrd/RSniffer.git
   cd RSniffer
   ```

2. Build the project:
   ```bash
   cargo build --release
   ```

## Usage

### Running with elevated privileges (recommended)

```bash
# Build first
cargo build

# Run with sudo
sudo ./target/debug/RSniffer
```

### Alternative: Set network capabilities (Linux only)

```bash
# Build the binary
cargo build

# Set capabilities (run once per build)
sudo setcap cap_net_raw,cap_net_admin=eip target/debug/RSniffer

# Run without sudo
./target/debug/RSniffer
```

### Example Output

```
Available network interfaces:
Device Number 0: "wlan0"
Device Number 1: "eth0"
Device Number 2: "lo"

Choose an Interface (0-2): 0

=== Packet 1 ===
Total Length: 66 bytes
🔗 Ethernet:
   Destination MAC: f4:c8:8a:18:3b:25
   Source MAC:      aa:7a:43:d8:07:10
   EtherType:       (Ipv4)
🌐 IPv4 Header:
   Header Length:   5 bytes
   Total Length:    52 bytes
   Protocol:        6 (TCP)
   Source IP:       37.202.225.217
   Destination IP:  192.168.43.190
🔀 TCP Header:
   37.202.225.217:1080 → 192.168.43.190:43370
   Sequence:        934834425
   Acknowledgment:  4165567737
   Flags:           24 (PSH, ACK)
   Window Size:     4853
   Service:         Unknown
```

## Code Structure

- **`main.rs`** - Main application logic with device selection and packet capture loop
- **`utils.rs`** - Protocol parsing utilities and packet analysis functions

## Learning Resources

The `utils.rs` file contains extensive documentation about network protocols and packet analysis, including:

- 📚 **Network stack overview** - How data flows through protocol layers
- 🔗 **Ethernet frame structure** - MAC addresses, EtherTypes, and frame format
- 🌐 **IPv4 header parsing** - IP addressing, protocol identification, and header fields
- 🚦 **TCP/UDP analysis** - Port numbers, flags, and connection states
- 📖 **Parsing examples** - Step-by-step packet dissection walkthrough

## Supported Protocols

### Layer 2 (Data Link)
- ✅ Ethernet
- ✅ ARP detection
- ✅ VLAN detection

### Layer 3 (Network)
- ✅ IPv4
- ✅ ICMP detection
- 🔄 IPv6 (detection only)

### Layer 4 (Transport)
- ✅ TCP (with flag analysis)
- ✅ UDP
- ✅ Service identification for common ports

### Application Layer Services
- HTTP (port 80)
- HTTPS (port 443)
- SSH (port 22)
- DNS (port 53)
- SMTP, POP3, IMAP
- And more...

## Troubleshooting

### Permission Errors
If you see "Operation not permitted":
```bash
sudo ./target/debug/RSniffer
```

### No Interfaces Found
Make sure you have network interfaces available:
```bash
ip link show  # Linux
ifconfig      # macOS/BSD
```

### Build Errors
Ensure libpcap development headers are installed (see Prerequisites section).

## Contributing

Feel free to submit issues and enhancement requests! Areas for improvement:
- IPv6 support
- More application layer protocols
- Packet filtering capabilities
- Export to PCAP format
- GUI interface


## Disclaimer

This tool is for educational and network troubleshooting purposes. Ensure you have proper authorization before capturing network traffic on any network you don't own.
