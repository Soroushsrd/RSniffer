use crate::types::Protocol;
use core::fmt;
use std::{error::Error, net::IpAddr};

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
    packet_size: usize,
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
            if packet.packet_size < min_size {
                return false;
            }
        }

        if let Some(max_size) = self.packet_size_max {
            if packet.packet_size > max_size {
                return false;
            }
        }
        true
    }
}

impl std::fmt::Display for Filter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut filter_str = String::with_capacity(70);

        if let Some(src_ip) = self.src_ip {
            filter_str.push_str(format!("\tSource Ip: {}\n", src_ip).as_str());
        }

        if let Some(src_port) = self.src_port {
            filter_str.push_str(format!("\tSource Port: {}\n", src_port).as_str());
        }
        if let Some(dst_ip) = self.dst_ip {
            filter_str.push_str(format!("\tDestination Ip: {}\n", dst_ip).as_str());
        }
        if let Some(dst_port) = self.dst_port {
            filter_str.push_str(format!("\tDestination Port: {}\n", dst_port).as_str());
        }
        if let Some(prtc) = self.protocol {
            filter_str.push_str(format!("\tProtocol: {}\n", prtc).as_str());
        }

        match (self.packet_size_min, self.packet_size_max) {
            (Some(min), Some(max)) => {
                filter_str.push_str(format!("\tPacket Size = {}..{}", min, max).as_str())
            }
            (Some(min), None) => filter_str.push_str(format!("\tPacket Size>={}", min).as_str()),
            (None, Some(max)) => filter_str.push_str(format!("\tPacket Size<={}", max).as_str()),
            (None, None) => {}
        }

        if filter_str.is_empty() {
            write!(f, "Filter: <empty>",)
        } else {
            write!(f, "Filter:\n{}", filter_str)
        }
    }
}

#[derive(Debug)]
pub enum FilterError {
    InvalidIp(String),
    InvalidPortRange,
}
impl fmt::Display for FilterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FilterError::InvalidIp(text) => write!(f, "Invalid IP: {}", text),
            FilterError::InvalidPortRange => write!(f, "Invalid Port Range"),
        }
    }
}
impl Error for FilterError {}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn test_matches() -> Result<(), Box<dyn std::error::Error>> {
        let filter = Filter::default()
            .src_ip("127.0.0.1")?
            .src_port(8080)
            .dst_ip("127.0.0.1")?
            .dst_port(8000)
            .protocol(Protocol::Tcp)
            .packet_size_range(100, 1000)?;

        let packet_1 = PacketInfo {
            src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 8080,
            dst_port: 8000,
            protocol: Protocol::Tcp,
            packet_size: 600,
        };
        assert!(filter.matches(&packet_1), "Filter cant find the packet");
        let packet_2 = PacketInfo {
            src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 8000,
            dst_port: 8000,
            protocol: Protocol::Udp,
            packet_size: 600,
        };
        assert!(
            !filter.matches(&packet_2),
            "Filter shouldnt be able to find this packet"
        );

        Ok(())
    }
    #[test]
    fn test_build_filter() -> Result<(), Box<dyn std::error::Error>> {
        let filter = Filter::default()
            .src_ip("127.0.0.1")?
            .src_port(8080)
            .dst_ip("127.0.0.1")?
            .dst_port(8000)
            .protocol(Protocol::Tcp)
            .packet_size_range(100, 1000)?;

        assert_eq!(filter.src_ip, Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert_eq!(filter.dst_ip, Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert_eq!(filter.src_port, Some(8080));
        assert_eq!(filter.dst_port, Some(8000));
        assert_eq!(filter.protocol, Some(Protocol::Tcp));

        println!("{}", filter);
        Ok(())
    }
}
