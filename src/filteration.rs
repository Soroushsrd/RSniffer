use crate::types::{IPInfo, Protocol, TransportInfo};
use clap::Parser;
use core::fmt;
use std::{error::Error, net::IpAddr};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct FilterArgs {
    /// Source IP
    #[arg(short = 'i', long)]
    src_ip: Option<String>,

    /// Destination IP
    #[arg(short = 'd', long)]
    dst_ip: Option<String>,

    /// Source Port
    #[arg(short = 's', long)]
    port_source: Option<u16>,

    /// Destination Port
    #[arg(short = 'p', long)]
    port_destination: Option<u16>,

    /// Protocol Used for data transportation
    #[arg(short = 'r', long)]
    protocol: Option<String>,

    /// Minimum Packet Size
    #[arg(short, long)]
    min_pack_size: Option<u16>,

    /// Maximum Packet Size
    #[arg(short = 'x', long)]
    max_pack_size: Option<u16>,
}

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

impl TryFrom<FilterArgs> for Filter {
    type Error = FilterError;
    fn try_from(args: FilterArgs) -> std::result::Result<Self, Self::Error> {
        let mut filter = Filter::new();

        if let Some(src_ip) = args.src_ip {
            filter = filter.src_ip(src_ip)?;
        }

        if let Some(dst_ip) = args.dst_ip {
            filter = filter.dst_ip(dst_ip)?;
        }

        if let Some(src_port) = args.port_source {
            filter = filter.src_port(src_port);
        }

        if let Some(dst_port) = args.port_destination {
            filter = filter.dst_port(dst_port);
        }

        if let Some(protocol_str) = args.protocol {
            filter = filter.protocol(protocol_str);
        }

        if let Some(min_size) = args.min_pack_size {
            filter = filter.packet_size_min(min_size);
        }

        if let Some(max_size) = args.max_pack_size {
            filter = filter.packet_size_max(max_size);
        }
        return Ok(filter);
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
    IoError(String),
}

impl From<std::io::Error> for FilterError {
    fn from(value: std::io::Error) -> Self {
        return Self::IoError(value.to_string());
    }
}

impl fmt::Display for FilterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FilterError::InvalidIp(text) => write!(f, "Invalid IP: {}", text),
            FilterError::InvalidPortRange => write!(f, "Invalid Port Range"),
            FilterError::IoError(text) => write!(f, "Io Error: {}", text),
        }
    }
}
impl Error for FilterError {}
