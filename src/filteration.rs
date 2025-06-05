use crate::types::{IPInfo, Protocol, TransportInfo};
use core::fmt;
use std::{error::Error, net::IpAddr};

#[derive(Debug, Default, Clone)]
pub struct Filter {
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    protocol: Option<Protocol>,
    packet_size_min: Option<u16>,
    packet_size_max: Option<u16>,
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
            .map_err(|_| FilterError::InvalidIp(ip_in))?;
        self.src_ip = Some(ip);
        Ok(self)
    }
    pub fn dst_ip(mut self, ip: impl Into<String>) -> Result<Self, FilterError> {
        let ip_in: String = ip.into();
        let ip = ip_in
            .parse::<IpAddr>()
            .map_err(|_| FilterError::InvalidIp(ip_in))?;
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
    //TODO: Error handling
    pub fn protocol(mut self, pr: String) -> Self {
        self.protocol = Some(Protocol::try_from(pr).unwrap());
        self
    }
    pub fn packet_size_range(mut self, min: u16, max: u16) -> Result<Self, FilterError> {
        if min >= max {
            return Err(FilterError::InvalidPortRange);
        }

        self.packet_size_min = Some(min);
        self.packet_size_max = Some(max);
        Ok(self)
    }
    pub fn packet_size_min(mut self, size: u16) -> Self {
        self.packet_size_min = Some(size);
        self
    }
    pub fn packet_size_max(mut self, size: u16) -> Self {
        self.packet_size_max = Some(size);
        self
    }
    pub fn matches_ip_level(&self, ip_info: &IPInfo) -> bool {
        if let Some(src_ip) = self.src_ip {
            if src_ip != ip_info.src_ip {
                return false;
            }
        }
        if let Some(expected_dst) = self.dst_ip {
            if ip_info.dst_ip != expected_dst {
                return false;
            }
        }
        if let Some(expected_protocol) = self.protocol {
            if ip_info.protocol != expected_protocol {
                return false;
            }
        }

        if let Some(min_size) = self.packet_size_min {
            if ip_info.total_length < min_size {
                return false;
            }
        }

        if let Some(max_size) = self.packet_size_max {
            if ip_info.total_length > max_size {
                return false;
            }
        }
        true
    }

    pub fn matches_transport_level(&self, packet: &TransportInfo) -> bool {
        match packet {
            TransportInfo::Udp {
                src_port, dst_port, ..
            }
            | TransportInfo::Tcp {
                src_port, dst_port, ..
            } => {
                if let Some(expected_src_port) = self.src_port {
                    if *src_port != expected_src_port {
                        return false;
                    }
                }

                if let Some(expected_dst_port) = self.dst_port {
                    if *dst_port != expected_dst_port {
                        return false;
                    }
                }
            }
            _ => {
                if self.src_port.is_some() || self.dst_port.is_some() {
                    return false;
                }
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
