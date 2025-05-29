use crate::types::{EtherType, EthernetHeader, KnownPorts, Protocol};

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
    println!("   EtherType:       ({:?})", eth_header.ether_type.clone());

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
        "   Service:         {}",
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
