mod filteration;
mod types;
mod utils;
use clap::Parser;
use filteration::{Filter, FilterArgs, FilterError};
use pcap::{Capture, Device};
use std::io::Write;
use utils::parse_and_display_packet;

fn main() -> Result<(), FilterError> {
    let args = FilterArgs::parse();

    let filter = Filter::try_from(args)?;

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
