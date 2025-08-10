use std::net::Ipv4Addr;

use anyhow::Context as _;
use aya::{
    maps::{Array, RingBuf},
    programs::{Xdp, XdpFlags},
};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use rsniffer_common::{FilterConfig, IPPROTO_ICMP, IPPROTO_TCP, IPPROTO_UDP, PacketEvent};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,

    #[clap(long)]
    src_ip: Option<Ipv4Addr>,

    #[clap(long)]
    dst_ip: Option<Ipv4Addr>,

    #[clap(long)]
    src_port: Option<u16>,

    #[clap(long)]
    dst_port: Option<u16>,

    #[clap(long)]
    protocol: Option<String>,

    #[clap(long)]
    min_size: Option<u16>,

    #[clap(long)]
    max_size: Option<u16>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/rsniffer"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {e}");
    }

    let mut filter_config: Array<_, FilterConfig> =
        Array::try_from(ebpf.map_mut("FILTER_CONFIG").unwrap())?;

    let config = FilterConfig {
        src_ip_filter: opt.src_ip.map(u32::from).unwrap_or(0),
        dst_ip_filter: opt.dst_ip.map(u32::from).unwrap_or(0),
        src_port_filter: opt.src_port.unwrap_or(0),
        dst_port_filter: opt.dst_port.unwrap_or(0),
        protocol_filter: match opt.protocol.as_deref() {
            Some("tcp") => IPPROTO_TCP,
            Some("udp") => IPPROTO_UDP,
            Some("icmp") => IPPROTO_ICMP,
            _ => 0,
        },
        min_packet_size: opt.min_size.unwrap_or(0),
        max_packet_size: opt.max_size.unwrap_or(0),
        enabled: 1,
    };
    filter_config.set(0, config, 0)?;

    let program: &mut Xdp = ebpf.program_mut("rsniffer").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let mut ring_buf = RingBuf::try_from(ebpf.map("PACKET_EVENTS").unwrap())?;
    println!("eBPF packet sniffer started on interface {}", &opt.iface);

    let mut packet_count = 0;
    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                println!("Received Ctrl-C, shutting down...");
                break;
            }
            _ = tokio::time::sleep(tokio::time::Duration::from_millis(100)) => {
                // Process events from ring buffer
                while let Some(item) = ring_buf.next() {
                    let packet: PacketEvent = unsafe {
                        std::ptr::read_unaligned(item.as_ptr() as *const PacketEvent)
                    };

                    packet_count += 1;
                    display_packets(packet_count, &packet);
                }
            }
        }
    }
    println!("\nTotal packets captured: {packet_count}");

    Ok(())
}

fn display_packets(count: usize, packet: &PacketEvent) {
    println!("=== Packet {count} ===");

    let src_ip = Ipv4Addr::from(packet.src_ip);
    let dst_ip = Ipv4Addr::from(packet.dst_ip);
    match packet.protocol {
        IPPROTO_TCP => {
            println!(
                "TCP: {}:{} → {}:{}",
                src_ip, packet.src_port, dst_ip, packet.dst_port
            );
            println!("Flags: [{}]", format_tcp_flags(packet.tcp_flags));
            println!(
                "Service: {}",
                identify_service(packet.src_port, packet.dst_port)
            );
        }
        IPPROTO_UDP => {
            println!(
                "UDP: {}:{} → {}:{}",
                src_ip, packet.src_port, dst_ip, packet.dst_port
            );
            println!(
                "Service: {}",
                identify_service(packet.src_port, packet.dst_port)
            );
        }
        IPPROTO_ICMP => {
            println!("ICMP: {src_ip} → {dst_ip}");
        }
        _ => {
            println!("Protocol {}: {} → {}", packet.protocol, src_ip, dst_ip);
        }
    }
    println!("Size: {} bytes", packet.packet_size);
    println!("Timestamp: {}\n", packet.timestamp);
}

fn format_tcp_flags(flags: u8) -> String {
    let mut flag_names = Vec::new();

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

fn identify_service(src_port: u16, dst_port: u16) -> String {
    let port = if src_port < 1024 { src_port } else { dst_port };

    match port {
        20 => "FTP Data".to_string(),
        21 => "FTP Control".to_string(),
        22 => "SSH".to_string(),
        23 => "Telnet".to_string(),
        25 => "SMTP".to_string(),
        53 => "DNS".to_string(),
        67 => "DHCP Server".to_string(),
        68 => "DHCP Client".to_string(),
        80 => "HTTP".to_string(),
        110 => "POP3".to_string(),
        143 => "IMAP".to_string(),
        443 => "HTTPS".to_string(),
        993 => "IMAPS".to_string(),
        995 => "POP3S".to_string(),
        3306 => "MySQL".to_string(),
        3389 => "RDP".to_string(),
        5432 => "PostgreSQL".to_string(),
        _ => format!("Port {port}"),
    }
}
