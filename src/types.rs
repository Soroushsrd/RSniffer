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

use std::{fmt, net::IpAddr};

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
#[derive(Debug, Copy, PartialEq, Eq, Clone)]
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

impl TryFrom<String> for Protocol {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.to_lowercase().as_str() {
            "tcp" => Ok(Protocol::Tcp),
            "udp" => Ok(Protocol::Udp),
            "icmp" => Ok(Protocol::Icmp),
            "igmp" => Ok(Protocol::Igmp),
            "esp" => Ok(Protocol::Esp),
            _ => Err(format!("Unknown protocol: {}", value)),
        }
    }
}
impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::Icmp => write!(f, "ICMP"),
            Protocol::Tcp => write!(f, "TCP"),
            Protocol::Udp => write!(f, "UDP"),
            Protocol::Igmp => write!(f, "IGMP"),
            Protocol::Esp => write!(f, "ESP"),
            Protocol::Other => write!(f, "Other Protocols"),
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
#[repr(u16)]
pub enum KnownPorts {
    FTPData = 20,
    FTPControl = 21,
    Ssh = 22,
    Telnet = 23,
    Smtp = 25,
    Whois = 43,
    Dns = 53,
    Covia = 64,
    DHCPServer = 67,
    DHCPClient = 68,
    Http = 80,
    POP3 = 110,
    Ntp = 123,
    Imap = 143,
    Https = 443,
    Ldap = 389,
    Syslog = 514,
    Ldaps = 636,
    Imaps = 993,
    POP3S = 995,
    Mssql = 1433,
    Oracle = 1521,
    Docker = 2376,
    Mysql = 3306,
    Rdp = 3389,
    Postgresql = 5432,
    Git = 9418,
    Unknown(u16),
}

impl fmt::Display for KnownPorts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KnownPorts::FTPData => write!(f, "FTP Data (20)"),
            KnownPorts::FTPControl => write!(f, "FTP Control (21)"),
            KnownPorts::Ssh => write!(f, "SSH (22)"),
            KnownPorts::Telnet => write!(f, "Telnet (23)"),
            KnownPorts::Smtp => write!(f, "SMTP (25)"),
            KnownPorts::Whois => write!(f, "WHOIS (43)"),
            KnownPorts::Dns => write!(f, "DNS (53)"),
            KnownPorts::Covia => write!(f, "Covia (64)"),
            KnownPorts::DHCPServer => write!(f, "DHCP Server (67)"),
            KnownPorts::DHCPClient => write!(f, "DHCP Client (68)"),
            KnownPorts::Http => write!(f, "HTTP (80)"),
            KnownPorts::POP3 => write!(f, "POP3 (110)"),
            KnownPorts::Ntp => write!(f, "NTP (123)"),
            KnownPorts::Imap => write!(f, "IMAP (143)"),
            KnownPorts::Https => write!(f, "HTTPS (443)"),
            KnownPorts::Ldap => write!(f, "LDAP (389)"),
            KnownPorts::Syslog => write!(f, "SysLog (514)"),
            KnownPorts::Ldaps => write!(f, "LDAPS (636)"),
            KnownPorts::Imaps => write!(f, "IMAPS (993)"),
            KnownPorts::POP3S => write!(f, "POP3S (995)"),
            KnownPorts::Mssql => write!(f, "MsSql (1433)"),
            KnownPorts::Oracle => write!(f, "Oracle (1521)"),
            KnownPorts::Docker => write!(f, "Docker (2376)"),
            KnownPorts::Mysql => write!(f, "MySql (3306)"),
            KnownPorts::Rdp => write!(f, "RDP (3389)"),
            KnownPorts::Postgresql => write!(f, "PostgreSql (5432)"),
            KnownPorts::Git => write!(f, "Git (9418)"),
            KnownPorts::Unknown(port) => write!(f, "Unknown ({})", port),
        }
    }
}
impl From<u16> for KnownPorts {
    fn from(value: u16) -> Self {
        match value {
            20 => Self::FTPData,
            21 => Self::FTPControl,
            22 => Self::Ssh,
            23 => Self::Telnet,
            25 => Self::Smtp,
            43 => Self::Whois,
            53 => Self::Dns,
            64 => Self::Covia,
            67 => Self::DHCPServer,
            68 => Self::DHCPClient,
            80 => Self::Http,
            110 => Self::POP3,
            123 => Self::Ntp,
            143 => Self::Imap,
            443 => Self::Https,
            389 => Self::Ldap,
            514 => Self::Syslog,
            636 => Self::Ldaps,
            993 => Self::Imaps,
            995 => Self::POP3S,
            1433 => Self::Mssql,
            1521 => Self::Oracle,
            2376 => Self::Docker,
            3306 => Self::Mysql,
            3389 => Self::Rdp,
            5432 => Self::Postgresql,
            9418 => Self::Git,
            _ => Self::Unknown(value),
        }
    }
}
// Port Ranges:
//
// 0-1023: Well-known/system ports (require root)
// 1024-49151: Registered ports (assigned by IANA)
// 49152-65535: Dynamic/ephemeral ports (temporary)
//

#[derive(Clone)]
pub struct EthernetHeader {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ether_type: EtherType,
}

#[derive(Debug, Clone)]
pub struct IPInfo {
    pub version: u8,
    pub header_length: u8,
    pub total_length: u16,
    pub protocol: Protocol,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum TransportInfo {
    Tcp {
        src_port: u16,
        dst_port: u16,
        seq_num: u32,
        ack_num: u32,
        header_length: u8,
        flags: u8,
        window_size: u16,
        checksum: u16,
        urgent_pointer: u16,
        options: Option<Vec<u8>>,
    },
    Udp {
        src_port: u16,
        dst_port: u16,
        length: u16,
    },
    Icmp,
    Other,
}
