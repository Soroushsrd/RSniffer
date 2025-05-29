use crate::types::Protocol;
use std::net::IpAddr;

#[derive(Debug, Default)]
pub struct Filter {
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    protocol: Option<Protocol>,
    packet_size_min: Option<usize>,
    packet_size_max: Option<usize>,
}

#[derive(Debug)]
pub struct PacketInfo {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    protocol: Protocol,
    packet_size_min: usize,
    packet_size_max: usize,
}

#[allow(dead_code)]
impl Filter {
    pub fn new() -> Self {
        Filter::default()
    }
    pub fn src_ip(mut self, ip: impl Into<String>) -> Result<Self, FilterError> {
        let ip_in = ip.into();
        let ip = ip_in
            .parse::<IpAddr>()
            .map_err(|_| FilterError::InvalidIp(format!("{}", ip_in)))?;
        self.src_ip = Some(ip);
        Ok(self)
    }
    pub fn dst_ip(mut self, ip: impl Into<String>) -> Result<Self, FilterError> {
        let ip_in = ip.into();
        let ip = ip_in
            .parse::<IpAddr>()
            .map_err(|_| FilterError::InvalidIp(format!("{}", ip_in)))?;
        self.dst_ip = Some(ip);
        Ok(self)
    }

    pub fn src_port(mut self, port: u16) -> Self {
        self.src_port = Some(port);
        self
    }
    pub fn dst_port(mut self, port: u16) -> Self {
        self.dst_port = Some(port);
        self
    }
    pub fn protocol(mut self, pr: Protocol) -> Self {
        self.protocol = Some(pr);
        self
    }
    pub fn packet_size_range(mut self, min: usize, max: usize) -> Result<Self, FilterError> {
        if min >= max {
            return Err(FilterError::InvalidPortRange);
        }

        self.packet_size_min = Some(min);
        self.packet_size_max = Some(max);
        Ok(self)
    }
    pub fn packet_size_min(mut self, size: usize) -> Self {
        self.packet_size_min = Some(size);
        self
    }
    pub fn packet_size_max(mut self, size: usize) -> Self {
        self.packet_size_max = Some(size);
        self
    }
    pub fn matches(&self, packet: &PacketInfo) -> bool {
        if let Some(src_ip) = self.src_ip {
            if src_ip != packet.src_ip {
                return false;
            }
        }
        if let Some(expected_dst) = self.dst_ip {
            if packet.dst_ip != expected_dst {
                return false;
            }
        }

        if let Some(expected_src_port) = self.src_port {
            if packet.src_port != expected_src_port {
                return false;
            }
        }

        if let Some(expected_dst_port) = self.dst_port {
            if packet.dst_port != expected_dst_port {
                return false;
            }
        }

        if let Some(expected_protocol) = self.protocol {
            if packet.protocol != expected_protocol {
                return false;
            }
        }

        if let Some(min_size) = self.packet_size_min {
            if packet.packet_size_min < min_size {
                return false;
            }
        }

        if let Some(max_size) = self.packet_size_max {
            if packet.packet_size_max > max_size {
                return false;
            }
        }
        true
    }
}

impl std::fmt::Display for Filter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Filter Components Are:\n\tsource ip: {:?}\n\tdst ip: {:?}\n\tsrc port: {:?}\n\tdst ip: {:?}\n\tprotocol: {:?}\n\tpacket size min: {:?}\n\tpacket size max: {:?}\n",
            self.src_ip,
            self.dst_ip,
            self.src_port,
            self.dst_port,
            self.protocol,
            self.packet_size_min,
            self.packet_size_max
        )
    }
}

#[derive(Debug)]
pub enum FilterError {
    InvalidIp(String),
    InvalidPortRange,
}
