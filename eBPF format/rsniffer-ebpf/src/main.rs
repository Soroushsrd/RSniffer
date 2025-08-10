#![no_std]
#![no_main]

use core::slice;

use aya_ebpf::{
    bindings::xdp_action,
    helpers::r#gen::bpf_ktime_get_ns,
    macros::{map, xdp},
    maps::{Array, RingBuf},
    programs::XdpContext,
};
use rsniffer_common::{
    ETH_P_IP, FilterConfig, IPPROTO_ICMP, IPPROTO_TCP, IPPROTO_UDP, PacketEvent,
};

#[map]
static PACKET_EVENTS: RingBuf = RingBuf::with_byte_size(1024 * 1024, 0);

#[map]
static FILTER_CONFIG: Array<FilterConfig> = Array::with_max_entries(1, 0);

#[xdp]
pub fn rsniffer(ctx: XdpContext) -> u32 {
    match try_rsniffer(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_rsniffer(ctx: XdpContext) -> Result<u32, u32> {
    let data = ctx.data();
    let data_end = ctx.data_end();

    // min packet size (eth+ip)
    if data + 34 > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let eth_data = unsafe { slice::from_raw_parts(data as *const u8, 14) };
    let eth_type = u16::from_be_bytes([eth_data[12], eth_data[13]]);

    // only ethernet headers shall pass :)
    if eth_type != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip_offset = data + 14;
    let ip_data = unsafe { slice::from_raw_parts(ip_offset as *const u8, 20) };

    let version_ihl = ip_data[0];
    let version = (version_ihl >> 4) & 0x0F;
    let ihl = (version_ihl & 0x0F) * 4;
    let protocol = ip_data[9];
    let total_length = u16::from_be_bytes([ip_data[2], ip_data[3]]);

    // header len and version verification
    if version != 4 || ihl < 20 {
        return Ok(xdp_action::XDP_PASS);
    }

    // is the ip header complete?
    if ip_offset + ihl as usize > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    let src_ip = u32::from_be_bytes([ip_data[12], ip_data[13], ip_data[14], ip_data[15]]);
    let dst_ip = u32::from_be_bytes([ip_data[16], ip_data[17], ip_data[18], ip_data[19]]);

    let filter = unsafe {
        match FILTER_CONFIG.get_ptr(0) {
            Some(config) => &*config,
            None => return Ok(xdp_action::XDP_PASS),
        }
    };

    if filter.enabled == 0 {
        return Ok(xdp_action::XDP_PASS);
    }

    // Apply IP-level filters
    if filter.src_ip_filter != 0 && src_ip != filter.src_ip_filter {
        return Ok(xdp_action::XDP_PASS);
    }

    if filter.dst_ip_filter != 0 && dst_ip != filter.dst_ip_filter {
        return Ok(xdp_action::XDP_PASS);
    }

    // Convert protocol to our constants
    let proto_const = match protocol {
        6 => IPPROTO_TCP,
        17 => IPPROTO_UDP,
        1 => IPPROTO_ICMP,
        _ => return Ok(xdp_action::XDP_PASS),
    };

    if filter.protocol_filter != 0 && proto_const != filter.protocol_filter {
        return Ok(xdp_action::XDP_PASS);
    }
    if filter.min_packet_size != 0 && total_length < filter.min_packet_size {
        return Ok(xdp_action::XDP_PASS);
    }
    if filter.max_packet_size != 0 && total_length > filter.max_packet_size {
        return Ok(xdp_action::XDP_PASS);
    }
    let mut event = PacketEvent {
        src_ip,
        dst_ip,
        dst_port: 0,
        src_port: 0,
        protocol: proto_const,
        packet_size: total_length,
        tcp_flags: 0,
        timestamp: unsafe { bpf_ktime_get_ns() },
    };
    let transport_offset = ip_offset + ihl as usize;

    match protocol {
        6 => {
            if transport_offset + 20 <= data_end {
                let tcp_data = unsafe { slice::from_raw_parts(transport_offset as *const u8, 20) };
                event.src_port = u16::from_be_bytes([tcp_data[0], tcp_data[1]]);
                event.dst_port = u16::from_be_bytes([tcp_data[2], tcp_data[3]]);
                // bits 0-5 of byte 13
                event.tcp_flags = tcp_data[13] & 0x3F;

                if filter.src_port_filter != 0 && event.src_port != filter.src_port_filter {
                    return Ok(xdp_action::XDP_PASS);
                }

                if filter.dst_port_filter != 0 && event.dst_port != filter.dst_port_filter {
                    return Ok(xdp_action::XDP_PASS);
                }
            }
        }
        17 => {
            // UDP
            if transport_offset + 8 <= data_end {
                let udp_data = unsafe { slice::from_raw_parts(transport_offset as *const u8, 8) };

                event.src_port = u16::from_be_bytes([udp_data[0], udp_data[1]]);
                event.dst_port = u16::from_be_bytes([udp_data[2], udp_data[3]]);

                // Apply port filters
                if filter.src_port_filter != 0 && event.src_port != filter.src_port_filter {
                    return Ok(xdp_action::XDP_PASS);
                }
                if filter.dst_port_filter != 0 && event.dst_port != filter.dst_port_filter {
                    return Ok(xdp_action::XDP_PASS);
                }
            }
        }
        _ => { // no need to filter icmp or other protocols as they dont have ports}
        }
    }
    if let Some(mut entry) = PACKET_EVENTS.reserve::<PacketEvent>(0) {
        unsafe {
            let entry_ptr = entry.as_mut_ptr();
            *entry_ptr = event;
        }
        entry.submit(0);
    }
    Ok(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
