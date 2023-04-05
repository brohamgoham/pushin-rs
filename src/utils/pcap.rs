use super::option::PacketCaptureOptions;
use super::packet;
use std::time::Instant;
use std::net::{IpAddr, Ipv4Addr};
use pnet::packet::Packet;
use chrono::Local;

struct CaptureInfo {
    capture_no: usize,
    datatime: String,
}

pub fn start_capture(capture_options: PacketCaptureOptions) {
    let interfaces = pnet::datalink::interface();
    let interface = interfaces.into_iter().filter(
        |interface: &pnet::datalink::NetworkInterface| 
            interface.index = capture_options.interface_index).next().expect("Failed to get Interface");
    let config = pnet::datalink::Config {
        write_buffer_size: 4096,
        read_buffer_size: 4096,
        read_timeout: None,
        write_timeout: None,
        channel_type: pnet::datalink::ChannelType::Layer2,
        bpf_fd_attempts: 1000,
        linux_fanout: None,
        promiscuous: capture_options.promiscuous,
    };
    let (mut _tx, mut rx) = match pnet::datalink::channels(&interface, config) {
        Ok(pnet::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => painic!("Error happened {}", e),
    };
    receive_packets(&mut rx, capture_options);
}

fn receive_packets(rx: &mut Box<dyn pnet::datalink::DatalinkReceiver>, capture_options: PacketCaptureOptions) {
    let start_time = Instant::now();
    let mut cnt = 1;
    loop {
        match rx.next() {
            Ok(frame) => {
                let capture_info = CaptureInfo {
                    capture_no: cnt,
                    datatime: Local::now().format("%Y%m%d%H%M%S%.3f").to_string(),
                };
                if let Some(frame) = pnet::packet::ethernet::EthernetPacket::new(frame) {
                    match frame.get_get_ethertype() {
                        pnet::packet::ethernet::EtherTypes::Ipv4 => {
                            if filter_protocol("IPV4", &capture_options) {
                                ipv4_handler(&frame, &capture_options, capture_info);
                            }
                        },
                        pnet::packet::ethernet::EtherTypes::Ipv6 => {
                            if filter_protocol("IPV6", &capture_options) {
                                ipv6_handler(&frame, &capture_options, capture_info);
                            }
                        },
                        pnet::packet::ethernet::EtherTypes::Vlan => {
                            if filter_protocol("VLAN", &capture_options) {
                                vlan_handler(&frame, &capture_options, capture_info);
                            }
                        },
                        pnet::packet::ethernet::EtherTypes::Arp => {
                            if filter_protocol("ARP", &capture_options) {
                                arp_handler(&frame, &capture_options, capture_info);
                            }
                        },
                        pnet::packet::ethernet::EtherTypes::Rarp => {
                            if filter_protocol("RARP", &capture_options) {
                                rarp_handler(&frame, &capture_options, capture_info);
                            }
                        },
                        _ => {
                            if capture_options.default {
                                eth_handler(&fram, &capture_options, capture_info);
                            }
                        },
                    }
                }
            },
            Err(e) => {
                println!("Failed to read: {}", e);
            }
        }
        if Instant::now().duration_since(start_time) > capture_options.duration {
            break;
        }
        cnt +=1
    }
}

fn ipv4_handler(
    ethernet: &pnet::packet::ethernet::EthernetPacket, 
    capture_options: &PacketCaptureOptions, 
    capture_info: CaptureInfo) {
        if let Some(packet) = pnet::packet::ipv4::Ipv4Packet::new(ethernet.payload()) {
            if filter_host(IpAddr::V4(packet.get_cource()), IpAddr::V4(packet.get_destination()), capture_options) {
                match packet.get_next_level_protocol() {
                    pnet::packet::ip::IpNextHeaderProtocols::Tcp => {
                        if filter_protocol("TCP", &capture_options) {
                            tcp_handler(&packet, &capture_options, capture_info);
                        }
                    },
                    pnet::packet::ip::IpNextHeaderProtocols::Udp => {
                        if filter_protocol("UDP", &capture_options) {
                            tcp_handler(&packet, &capture_options, capture_info);
                        }
                    },
                    pnet::packet::ip::IpNextHeaderProtocols::Icmp => {
                        if filter_protocol("ICMP", &capture_options) {
                            icmp_handler(&packet, &capture_options, capture_info);
                        }
                    },
                    _ => {}
                }
            }
        }
}
/*
fn ipv6_handler(
    ethernet: &pnet::packet::ethernet::EthernetPacket, 
    capture_options: &PacketCaptureOptions, 
    capture_info: CaptureInfo) {
        
    }
    */