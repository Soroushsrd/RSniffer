use std::net::{IpAddr, Ipv4Addr};

use crate::{
    filteration::Filter,
    types::{EtherType, EthernetHeader, IPInfo, KnownPorts, Protocol, TransportInfo},
};

pub fn parse_and_display_packet(filter: &Filter, packet_num: usize, packet: &pcap::Packet) {
    println!("\n=== Packet {} ===", packet_num);
    // println!("Timestamp: {:?}", packet.header.ts);
    println!("Total Length: {} bytes", packet.data.len());

    if packet.data.len() < 14 {
        println!("Packet too short for Ethernet header");
        return;
    }

    // Parse Ethernet header (14 bytes)
    let eth_header = match parse_ehternet_header(&packet.data[0..14]) {
        Ok(header) => header,
        Err(e) => {
            eprintln!("Ethernet parsing error: {}", e);
            return;
        }
    };

    if eth_header.ether_type == EtherType::Ipv4 && packet.data.len() >= 34 {
        if let Err(e) = process_ip_packet(&filter, &packet.data[14..], eth_header) {
            eprintln!("IP processing error: {}", e);
        }
    }
}

fn process_ip_packet(
    filter: &Filter,
    data: &[u8],
    eth_header: EthernetHeader,
) -> Result<(), String> {
    let ip_info = parse_ip_header(data)?;

    if !filter.matches_ip_level(&ip_info) {
        return Ok(());
    }

    let transport_info = parse_transport_header(data, &ip_info)?;

    if !filter.matches_transport_level(&transport_info) {
        return Ok(());
    }

    display_packet(&eth_header, &ip_info, &transport_info);
    Ok(())
}

fn display_packet(eth_header: &EthernetHeader, ip_info: &IPInfo, transport_info: &TransportInfo) {
    println!("🔗 Ethernet:");
    println!("   Destination MAC: {}", format_mac(&eth_header.dst_mac));
    println!("   Source MAC:      {}", format_mac(&eth_header.src_mac));
    println!("   EtherType:       ({:?})", eth_header.ether_type.clone());
    println!("🌐 IPv{} Header:", ip_info.version);
    println!("   Header Length:   {} bytes", ip_info.header_length);
    println!("   Total Length:    {} bytes", &ip_info.total_length);
    println!("   Protocol:        {} ", &ip_info.protocol,);
    println!("   Source IP:       {}", ip_info.src_ip);
    println!("   Destination IP:  {}", ip_info.dst_ip);

    match transport_info {
        TransportInfo::Tcp {
            src_port,
            dst_port,
            seq_num,
            ack_num,
            header_length,
            flags,
            window_size,
            ..
        } => {
            println!("🔀 TCP Header:");
            println!("  TCP Header Length: {}", header_length);
            println!(
                "   {}:{} → {}:{}",
                ip_info.src_ip, src_port, ip_info.dst_ip, dst_port
            );
            println!("   Sequence:        {}", seq_num);
            println!("   Acknowledgment:  {}", ack_num);
            println!(
                "   Flags:           {} ({})",
                flags,
                format_tcp_flags(*flags)
            );
            println!("   Window Size:     {}", window_size);
            println!(
                "   Service:         {}",
                identify_service(*src_port, *dst_port)
            );
        }
        TransportInfo::Udp {
            src_port,
            dst_port,
            length,
        } => {
            println!("📡 UDP Header:");
            println!(
                "   {}:{} → {}:{}",
                ip_info.src_ip, src_port, ip_info.src_ip, dst_port
            );
            println!("   Length:          {} bytes", length);
            println!(
                "   Service:         {:?}",
                identify_service(*src_port, *dst_port)
            );
        }
        TransportInfo::Icmp => println!("ICP Protocol"),
        TransportInfo::Other => println!("Other Protocols"),
    }
}
fn parse_transport_header(data: &[u8], ip_info: &IPInfo) -> Result<TransportInfo, String> {
    let transport_data = &data[ip_info.header_length as usize..];
    match ip_info.protocol {
        Protocol::Tcp => {
            if transport_data.len() < 20 {
                return Err("Insufficient data for TCP header".to_string());
            }
            let header_length = (transport_data[12] >> 4) * 4;
            let options = if header_length > 20 && transport_data.len() > header_length as usize {
                Some(transport_data[20..header_length as usize].to_vec())
            } else {
                None
            };

            Ok(TransportInfo::Tcp {
                src_port: u16::from_be_bytes([transport_data[0], transport_data[1]]),
                dst_port: u16::from_be_bytes([transport_data[2], transport_data[3]]),
                seq_num: u32::from_be_bytes([
                    transport_data[4],
                    transport_data[5],
                    transport_data[6],
                    transport_data[7],
                ]),
                ack_num: u32::from_be_bytes([
                    transport_data[8],
                    transport_data[9],
                    transport_data[10],
                    transport_data[11],
                ]),
                header_length,
                flags: transport_data[13],
                window_size: u16::from_be_bytes([transport_data[14], transport_data[15]]),
                checksum: u16::from_be_bytes([transport_data[16], transport_data[17]]),
                urgent_pointer: u16::from_be_bytes([transport_data[18], transport_data[19]]),
                options,
            })
        }
        Protocol::Udp => {
            if transport_data.len() < 8 {
                return Err("Insufficient data for UDP header".to_string());
            }
            Ok(TransportInfo::Udp {
                src_port: u16::from_be_bytes([transport_data[0], transport_data[1]]),
                dst_port: u16::from_be_bytes([transport_data[2], transport_data[3]]),
                length: u16::from_be_bytes([transport_data[4], transport_data[5]]),
            })
        }
        Protocol::Icmp => Ok(TransportInfo::Icmp),
        _ => Ok(TransportInfo::Other),
    }
}

fn parse_ip_header(data: &[u8]) -> Result<IPInfo, String> {
    if data.len() < 20 {
        return Err("Insufficient data for IP header".to_string());
    }

    let header_length = (data[0] & 0x0F) * 4;
    if data.len() < header_length as usize {
        return Err("Truncated IP header".to_string());
    }
    Ok(IPInfo {
        version: (data[0] >> 4) & 0x0F,
        header_length,
        total_length: u16::from_be_bytes([data[2], data[3]]),
        protocol: Protocol::from(data[9]),
        src_ip: IpAddr::V4(Ipv4Addr::new(data[12], data[13], data[14], data[15])),
        dst_ip: IpAddr::V4(Ipv4Addr::new(data[16], data[17], data[18], data[19])),
    })
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
