// When data travels over a network, it gets wrapped in multiple layers of headers,
// like putting a letter in multiple envelopes:
//
// Application Data
// ↓ (wrap in TCP/UDP header)
// TCP/UDP + Application Data
// ↓ (wrap in IP header)
// IP + TCP/UDP + Application Data
// ↓ (wrap in Ethernet header)
// Ethernet + IP + TCP/UDP + Application Data
// ↓ (send over wire)
//
// Every device on an Ethernet network has a unique MAC address.
//
// MAC (Media Access Control) Address:
// Length: 6 bytes (48 bits)
// Format: Usually written as aa:bb:cc:dd:ee:ff or aa-bb-cc-dd-ee-ff
// Purpose: Hardware-level addressing within a local network
// Scope: Only meaningful on the local network segment
//
// Example MAC: f4:c8:8a:18:3b:25
// f4:c8:8a = Manufacturer identifier (OUI - Organizationally Unique Identifier)
// 18:3b:25 = Device-specific identifier assigned by manufacturer/
//
// Special MAC Addresses:
// ff:ff:ff:ff:ff:ff = Broadcast (send to all devices)
// 01:xx:xx:xx:xx:xx = Multicast (send to group)
//
// Ethernet frame structure
// ┌─────────────────┬─────────────────┬───────────┬─────────────┬─────┐
// │ Destination MAC │   Source MAC    │ EtherType │   Payload   │ FCS │
// │    (6 bytes)    │   (6 bytes)     │ (2 bytes) │ (46-1500)   │(4b) │
// └─────────────────┴─────────────────┴───────────┴─────────────┴─────┘
//
// Destination MAC (6 bytes): Where the packet should go
// Source MAC (6 bytes): Where the packet came from
// EtherType (2 bytes): What type of data is in the payload
// Payload (46-1500 bytes): The actual data (IP packet, ARP, etc.)
// FCS (4 bytes): Frame Check Sequence (error detection) - usually stripped by NIC

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum EtherType {
    Ipv4 = 0x0800,
    Arp = 0x0806,
    Ipv6 = 0x86DD,
    Vlan = 0x8100,
    PppoeDiscovery = 0x8863,
    PppoeSession = 0x8864,
}

impl TryFrom<&[u8]> for EtherType {
    type Error = String;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() < 2 {
            return Err("Not Enough bytes for EtherType".to_string());
        }

        let value = u16::from_be_bytes([value[0], value[1]]);

        match value {
            0x0800 => Ok(Self::Ipv4),
            0x0806 => Ok(Self::Arp),
            0x86DD => Ok(Self::Ipv6),
            0x8100 => Ok(Self::Vlan),
            0x8863 => Ok(Self::PppoeDiscovery),
            0x8864 => Ok(Self::PppoeSession),
            _ => Err(format!("Unkown EtherType: 0x{:04X}", value)),
        }
    }
}

// When EtherType is IPv4 (0x0800), the payload contains and IPv4 packet:
// 0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// ┌───┬───────┬───────────────┬─────────────────────────────────────┐
// │Ver│  IHL  │    ToS/DSCP   │             Total Length            │
// ├───┴───────┼───────────────┼─────────────────────────────────────┤
// │           │               │                                     │
// │    Identification         │Flags│      Fragment Offset         │
// ├───────────────────────────┼─────┼─────────────────────────────────┤
// │    TTL    │   Protocol    │         Header Checksum             │
// ├───────────┼───────────────┼─────────────────────────────────────┤
// │                    Source IP Address                           │
// ├─────────────────────────────────────────────────────────────────┤
// │                  Destination IP Address                        │
// ├─────────────────────────────────────────────────────────────────┤
// │                    Options (if IHL > 5)                        │
// └─────────────────────────────────────────────────────────────────┘
//
// Key fields that must be parsed are:
// version,      => (data[0] >> 4) & 0x0F
// header length,=> (data[0] & 0x0F)*4
// total length, => u16::from_be_bytes([data[2],data[3]])
// protocol,     => data[9]
// source ip,    => data[12..16]
// dest ip       => data[16..20]
//
#[derive(Debug)]
pub enum Protocol {
    Icmp = 1, // Internet control msg protocol (ping, errors)
    Tcp = 6,  // Transmission control protocol
    Udp = 17, // User Datagram protocol
    Igmp = 2, // Internet Group management
    Esp = 50, // Generic routing encapsulation
    Other,    // Encrypted security payload
}

impl From<u8> for Protocol {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::Icmp,
            6 => Self::Tcp,
            17 => Self::Udp,
            2 => Self::Igmp,
            50 => Self::Esp,
            _ => Self::Other,
        }
    }
}

// IPv4 Address:
//
// Length: 4 bytes (32 bits)
// Format: Dotted decimal notation (e.g., 192.168.1.1)
// Classes:
//
// Class A: 1.0.0.0 to 126.255.255.255 (large networks)
// Class B: 128.0.0.0 to 191.255.255.255 (medium networks)
// Class C: 192.0.0.0 to 223.255.255.255 (small networks)
//
//
// Private IP Ranges (RFC 1918):
//
// 10.0.0.0/8 (10.0.0.0 to 10.255.255.255)
// 172.16.0.0/12 (172.16.0.0 to 172.31.255.255)
// 192.168.0.0/16 (192.168.0.0 to 192.168.255.255)
//
//
//
// TCP Payload takes this shape:
// 0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// ┌─────────────────────────────────┬─────────────────────────────────┐
// │          Source Port            │        Destination Port         │
// ├─────────────────────────────────┴─────────────────────────────────┤
// │                        Sequence Number                           │
// ├───────────────────────────────────────────────────────────────────┤
// │                    Acknowledgment Number                         │
// ├───┬───┬─┬─┬─┬─┬─┬─┬─┬─┬─────────────────────────────────────────────┤
// │HL │Res│C│E│U│A│P│R│S│F│            Window Size                   │
// ├───┴───┴─┴─┴─┴─┴─┴─┴─┴─┴─────────────────────────────────────────────┤
// │           Checksum              │         Urgent Pointer          │
// ├─────────────────────────────────┴─────────────────────────────────┤
// │                    Options (if HL > 5)                           │
// └───────────────────────────────────────────────────────────────────┘
//
// TCP Flags:
// FIN(0x01) Finish - no more data to be sent
// SYN(0x02) Synchronize - establish connection
// RST(0x04) Reset - Abort connection
// PSH(0x08) Push - Send data immediately
// ACK(0x10) Acknowledgement - Acknowledge received data
// URG(0x20) Urgent - Urgent data present
//
// Common Flag Combinations:
//
// SYN = Connection request
// SYN + ACK = Connection accepted
// ACK = Normal data transfer
// FIN + ACK = Connection termination
// RST = Connection reset/error
//
// UDP Protocol
// 0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// ┌─────────────────────────────────┬─────────────────────────────────┐
// │          Source Port            │        Destination Port         │
// ├─────────────────────────────────┼─────────────────────────────────┤
// │            Length               │           Checksum              │
// └─────────────────────────────────┴─────────────────────────────────┘

#[derive(Debug)]
pub enum KnownPorts {
    FTPData = 20,
    FTPControl = 21,
    Ssh = 22,
    Telnet = 23,
    Smtp = 25,
    Dns = 53,
    DHCPServer = 67,
    DHCPClient = 68,
    Http = 80,
    POP3 = 110,
    Imap = 143,
    Https = 443,
    Imaps = 993,
    POP3S = 995,
    Unknown,
}

impl From<u16> for KnownPorts {
    fn from(value: u16) -> Self {
        match value {
            20 => Self::FTPData,
            21 => Self::FTPControl,
            22 => Self::Ssh,
            23 => Self::Telnet,
            25 => Self::Smtp,
            53 => Self::Dns,
            67 => Self::DHCPServer,
            68 => Self::DHCPClient,
            80 => Self::Http,
            110 => Self::POP3,
            143 => Self::Imap,
            443 => Self::Https,
            993 => Self::Imaps,
            995 => Self::POP3S,
            _ => Self::Unknown,
        }
    }
}
// Port Ranges:
//
// 0-1023: Well-known/system ports (require root)
// 1024-49151: Registered ports (assigned by IANA)
// 49152-65535: Dynamic/ephemeral ports (temporary)
//

pub struct EthernetHeader {
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    ether_type: EtherType,
}

pub fn parse_and_display_packet(packet_num: usize, packet: &pcap::Packet) {
    println!("\n=== Packet {} ===", packet_num);
    // println!("Timestamp: {:?}", packet.header.ts);
    println!("Total Length: {} bytes", packet.data.len());

    if packet.data.len() < 14 {
        println!("Packet too short for Ethernet header");
        return;
    }

    // Parse Ethernet header (14 bytes)
    let eth_header = parse_ehternet_header(&packet.data[0..14]).unwrap();
    println!("🔗 Ethernet:");
    println!("   Destination MAC: {}", format_mac(&eth_header.dst_mac));
    println!("   Source MAC:      {}", format_mac(&eth_header.src_mac));
    println!(
        "   EtherType:       ({:?})",
        eth_header.ether_type.clone()
    );

    // Check if it's an IP packet
    if eth_header.ether_type == EtherType::Ipv4 && packet.data.len() >= 34 {
        parse_ip_packet(&packet.data[14..]);
    }
}

fn parse_ip_packet(data: &[u8]) {
    if data.len() < 20 {
        eprintln!("Packet too short as an IP header");
        return;
    }

    let version = (data[0] >> 4) & 0x0F;
    let header_length = data[0] & 0x0F;
    let protocol = data[9];
    let src_ip = format!("{}.{}.{}.{}", data[12], data[13], data[14], data[15]);
    let dst_ip = format!("{}.{}.{}.{}", data[16], data[17], data[18], data[19]);
    let total_length = u16::from_be_bytes([data[2], data[3]]);

    println!("🌐 IPv{} Header:", version);
    println!("   Header Length:   {} bytes", header_length);
    println!("   Total Length:    {} bytes", total_length);
    println!(
        "   Protocol:        {} ({:?})",
        protocol,
        Protocol::from(protocol)
    );
    println!("   Source IP:       {}", src_ip);
    println!("   Destination IP:  {}", dst_ip);

    if data.len() > header_length as usize {
        let transport_data = &data[header_length as usize..];
        match protocol {
            6 => parse_tcp_header(transport_data, &src_ip, &dst_ip),
            17 => parse_udp_header(transport_data, &src_ip, &dst_ip),
            1 => println!("ICMP Packet"),
            _ => println!("Other Protocols: {}", protocol),
        }
    }
}

fn parse_tcp_header(data: &[u8], src_ip: &str, dst_ip: &str) {
    if data.len() < 20 {
        eprintln!("TCP header is too short!");
        return;
    }

    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let seq_num = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let ack_num = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let flags = data[13];
    let window_size = u16::from_be_bytes([data[14], data[15]]);

    println!("🔀 TCP Header:");
    println!("   {}:{} → {}:{}", src_ip, src_port, dst_ip, dst_port);
    println!("   Sequence:        {}", seq_num);
    println!("   Acknowledgment:  {}", ack_num);
    println!(
        "   Flags:           {} ({})",
        flags,
        format_tcp_flags(flags)
    );
    println!("   Window Size:     {}", window_size);
    println!(
        "   Service:         {:?}",
        identify_service(src_port, dst_port)
    );
}

fn parse_udp_header(data: &[u8], src_ip: &str, dst_ip: &str) {
    if data.len() < 8 {
        eprint!("UDP header is too short");
        return;
    }

    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let length = u16::from_be_bytes([data[4], data[5]]);

    println!("📡 UDP Header:");
    println!("   {}:{} → {}:{}", src_ip, src_port, dst_ip, dst_port);
    println!("   Length:          {} bytes", length);
    println!(
        "   Service:         {:?}",
        identify_service(src_port, dst_port)
    );
}

fn format_mac(mac: &[u8; 6]) -> String {
    // mac addresses are usually and conventionally shown in lowercase {:02x}
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

fn format_tcp_flags(flags: u8) -> String {
    let mut flag_names = Vec::with_capacity(6);
    if flags & 0x01 != 0 {
        flag_names.push("FIN");
    }
    if flags & 0x02 != 0 {
        flag_names.push("SYN");
    }
    if flags & 0x04 != 0 {
        flag_names.push("RST");
    }
    if flags & 0x08 != 0 {
        flag_names.push("PSH");
    }
    if flags & 0x10 != 0 {
        flag_names.push("ACK");
    }
    if flags & 0x20 != 0 {
        flag_names.push("URG");
    }

    if flag_names.is_empty() {
        "None".to_string()
    } else {
        flag_names.join(", ")
    }
}

fn identify_service(src_port: u16, dst_port: u16) -> KnownPorts {
    let port = if src_port < 1024 { src_port } else { dst_port };
    KnownPorts::from(port)
}

fn parse_ehternet_header(data: &[u8]) -> Result<EthernetHeader, String> {
    if data.len() < 14 {
        return Err("Not Enough data for Ethernet header".to_string());
    }

    Ok(EthernetHeader {
        dst_mac: [data[0], data[1], data[2], data[3], data[4], data[5]],
        src_mac: [data[6], data[7], data[8], data[9], data[10], data[11]],
        ether_type: EtherType::try_from(&data[12..14])?,
    })
}
