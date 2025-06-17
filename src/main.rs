mod filteration;
mod types;
mod utils;
use std::io::Write;

use anyhow::{Context, Result};
use clap::Parser;
use filteration::Filter;
use pcap::{Capture, Device};
use utils::parse_and_display_packet;

fn main() -> Result<()> {
    let args = FilterArgs::parse();
    //TODO: How to make sure FilterErrors are compatible with Box dyn std errors
    //so that we could use ? instead of unwrap
    // let filter = Filter::default()
    //     .src_ip(args.src_ip)
    //     .unwrap()
    //     .dst_ip(args.dst_ip)
    //     .unwrap()
    //     .src_port(args.port_source)
    //     .dst_port(args.port_destination)
    //     .protocol(args.protocol)
    //     .packet_size_min(args.min_pack_size)
    //     .packet_size_max(args.max_pack_size);
    //

    let filter = build_filter(args)?;

    let devices = Device::list().unwrap();
    if devices.is_empty() {
        eprintln!("No Device Available");
        return Ok(());
    }
    for (idx, device) in devices.iter().enumerate() {
        println!("Device Number {}: {:#?}", idx, device.name);
    }
    print!("Choose an Interface (0-{}):", devices.len() - 1);

    std::io::stdout().flush()?;
    let mut input = String::new();

    std::io::stdin().read_line(&mut input)?;

    let selected_idx = match input.trim().parse::<usize>() {
        Ok(id) if id < devices.len() => id,

        _ => {
            eprintln!("Device ID Out Of Bound! Selecting the default (0).");
            0
        }
    };
    let selected_device = devices[selected_idx].clone();
    println!("Selected  {:#?}", selected_device);

    let mut cap = Capture::from_device(selected_device)
        .unwrap()
        .open()
        .unwrap();

    let mut packet_count = 0;
    loop {
        match cap.next_packet() {
            Ok(packet) => {
                packet_count += 1;
                parse_and_display_packet(&filter, packet_count, &packet);
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => {
                eprintln!("Error capturing packet: {}", e);
                break;
            }
        }
    }
    Ok(())
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct FilterArgs {
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

//TODO: a better way to do this !
fn build_filter(args: FilterArgs) -> Result<Filter> {
    let mut filter = Filter::new();

    if let Some(src_ip) = args.src_ip {
        filter = filter.src_ip(src_ip).context("Invalid source IP")?;
    }

    if let Some(dst_ip) = args.dst_ip {
        filter = filter.dst_ip(dst_ip).context("Invalid destination IP")?;
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

    // Validate size range if both are provided
    if let (Some(min), Some(max)) = (args.min_pack_size, args.max_pack_size) {
        if min >= max {
            anyhow::bail!("Minimum packet size must be less than maximum");
        }
    }

    Ok(filter)
}
