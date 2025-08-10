#![no_std]

#[repr(C)]
#[derive(Copy, Clone)]
pub struct PacketEvent {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub packet_size: u16,
    pub tcp_flags: u8,
    pub timestamp: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct FilterConfig {
    pub src_ip_filter: u32,
    pub dst_ip_filter: u32,
    pub src_port_filter: u16,
    pub dst_port_filter: u16,
    pub protocol_filter: u8,
    pub min_packet_size: u16,
    pub max_packet_size: u16,
    pub enabled: u8,
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self {
            src_ip_filter: 0,
            dst_ip_filter: 0,
            src_port_filter: 0,
            dst_port_filter: 0,
            protocol_filter: 0,
            min_packet_size: 0,
            max_packet_size: 0,
            enabled: 1,
        }
    }
}

// protocol consts
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
pub const IPPROTO_ICMP: u8 = 1;

// tcp flags
pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;
pub const TCP_URG: u8 = 0x20;

/// ethertype constants
pub const ETH_P_IP: u16 = 0x0800;

#[cfg(feature = "aya")]
unsafe impl aya::Pod for FilterConfig {}

#[cfg(feature = "aya")]
unsafe impl aya::Pod for PacketEvent {}
