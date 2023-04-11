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
    let interfaces = pnet::datalink::interfaces();
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
    let (mut _tx, mut rx) = match pnet::datalink::channel(&interface, config) {
        Ok(pnet::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened {}", e),
    };
    receive_packets(&mut rx, capture_options);
}

fn receive_packets(rx: &mut Box<dyn pnet::datalink::DataLinkReceiver>, capture_options: PacketCaptureOptions) {
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
                    match frame.get_ethertype() {
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
                                eth_handler(&frame, &capture_options, capture_info);
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
            if filter_host(IpAddr::V4(packet.get_source()), IpAddr::V4(packet.get_destination()), capture_options) {
                match packet.get_next_level_protocol() {
                    pnet::packet::ip::IpNextHeaderProtocols::Tcp => {
                        if filter_protocol("TCP", &capture_options) {
                            tcp_handler(&packet, &capture_options, capture_info);
                        }
                    },
                    pnet::packet::ip::IpNextHeaderProtocols::Udp => {
                        if filter_protocol("UDP", &capture_options) {
                            udp_handler(&packet, &capture_options, capture_info);
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

fn ipv6_handler(
    ethernet: &pnet::packet::ethernet::EthernetPacket, 
    capture_options: &PacketCaptureOptions, 
    capture_info: CaptureInfo
) {
    if let Some(packet) = pnet::packet::ipv6::Ipv6Packet::new(ethernet.payload()) {
        if filter_host(IpAddr::V6(packet.get_source()), IpAddr::V6(packet.get_destination()), capture_options) {
            match packet.get_next_header() {
                pnet::packet::ip::IpNextHeaderProtocols::Tcp => {
                    if filter_protocol("TCP", &capture_options) {
                        tcp_handler_v6(&packet, &capture_options, capture_info);
                    }
                },
                pnet::packet::ip::IpNextHeaderProtocols::Udp => {
                    if filter_protocol("UDP", &capture_options) {
                        udp_handler_v6(&packet, &capture_options, capture_info)
                    }
                },
                pnet::packet::ip::IpNextHeaderProtocols::Icmp => {
                    if filter_protocol("ICMP", &capture_options) {
                        icmpv6_handler(&packet, &capture_options, capture_info)
                    }
                },
                _ => {}
            }
        }
    }         
}   

/// Ether Net Handler
fn eth_handler(
    ethernet: &pnet::packet::ethernet::EthernetPacket,
    _capture_options: &PacketCaptureOptions,
    capture_info: CaptureInfo
) {
    print!("[{}] [{}]", capture_info.capture_no, capture_info.datatime);
    println!("[{}, {} -> {}, Length {}] "
    , packet::get_ethertype_string(ethernet.get_ethertype())
    , ethernet.get_source()
    , ethernet.get_destination()
    , ethernet.payload().len());
}

/// VLAN Handler
fn vlan_handler(
    ethernet: &pnet::packet::ethernet::EthernetPacket,
    _capture_options: &PacketCaptureOptions,
    capture_info: CaptureInfo
) {
    if let Some(vlan) = pnet::packet::vlan::VlanPacket::new(ethernet.payload()) {
        print!("[{}] [{}]", capture_info.capture_no, capture_info.datatime);
        println!("[VLAN, {} -> {}, ID {}, Length {}]"
        , ethernet.get_source()
        , ethernet.get_destination()
        , vlan.get_vlan_identifier()
        , vlan.payload().len());
    }
}
/// ARP Handler
/// Address Resolution Protocol to resolve IP Addr to MAC addr
/// ARP is to get MAC Addres RARP is to get IP Addr ex ARP Spoofing
/// by capturing ARP packets we can detect sus activities on our network
fn arp_handler(
    ethernet: &pnet::packet::ethernet::EthernetPacket,
    capture_options: &PacketCaptureOptions,
    capture_info: CaptureInfo
) {
    if let Some(arp) = pnet::packet::arp::ArpPacket::new(ethernet.payload()) {
        if filter_host(IpAddr::V4(arp.get_sender_proto_addr()), IpAddr::V4(arp.get_target_proto_addr()), capture_options) {
            print!("[{}] [{}] ", capture_info.capture_no, capture_info.datatime);
            println!("[ARP, {}({}) -> {}({}), Length {}]"
            , arp.get_sender_proto_addr().to_string()
            , arp.get_sender_hw_addr().to_string()
            , arp.get_target_proto_addr().to_string()
            , arp.get_target_hw_addr().to_string()
            , arp.payload().len());
        }
    }
}
/// RARP Hanler
/// Reverse Addr Resolution Protocol
/// We can use  to map the network of our target
fn rarp_handler(
    ethernet: &pnet::packet::ethernet::EthernetPacket,
    _capture_options: &PacketCaptureOptions,
    capture_info: CaptureInfo
) {
    if let Some(arp) = pnet::packet::arp::ArpPacket::new(ethernet.payload()) {
        print!("[{}] [{}]", capture_info.capture_no, capture_info.datatime);
        println!("[RARP, {}({}) -> {}({}), Length {}]"
        , arp.get_sender_proto_addr().to_string()
        , arp.get_sender_hw_addr().to_string()
        , arp.get_target_proto_addr().to_string()
        , arp.get_target_hw_addr().to_string()
        , arp.payload().len());
    }
}


/// TCP handler for IPV4
fn tcp_handler(
    packet: &pnet::packet::ipv4::Ipv4Packet,
    capture_options: &PacketCaptureOptions,
    capture_info: CaptureInfo
) {
    let tcp = pnet::packet::tcp::TcpPacket::new(packet.payload());
    if let Some(tcp) = tcp {
        if filter_port(tcp.get_source(), tcp.get_destination(), capture_options) {
            print!("[{}] [{}]", capture_info.capture_no, capture_info.datatime);
            println!("[IPv4, {}:{} -> {}:{}, TCP {}, Length {}]"
            , packet.get_source()
            , tcp.get_source()
            , packet.get_destination()
            , tcp.get_destination()
            , packet::get_tcp_flag_string(tcp.get_flags())
            , tcp.payload().len());
        }
    }
}

/// TCP handler for IPV6
fn tcp_handler_v6(
    packet: &pnet::packet::ipv6::Ipv6Packet,
    capture_options: &PacketCaptureOptions,
    capture_info: CaptureInfo
) {
    let tcp = pnet::packet::tcp::TcpPacket::new(packet.payload());
    if let Some(tcp) = tcp {
        if filter_port(tcp.get_source(), tcp.get_destination(), capture_options) {
            print!("[{}] [{}]", capture_info.capture_no, capture_info.datatime);

            println!(" [IPv4, {}:{} -> {}:{},TCP {}, Length {}]"
            , packet.get_source()
            , tcp.get_source()
            , packet.get_destination()
            , tcp.get_destination()
            , packet::get_tcp_flag_string(tcp.get_flag())
            , tcp.payload().len());
        }
    }
}

/// UDP Handler for IPV4
fn udp_handler(
    packet: &pnet::packet::ipv4::Ipv4Packet,
    capture_options: &PacketCaptureOptions,
    capture_info: CaptureInfo
) {
    let udp = pnet::packet::udp::UdpPacket::new(packet.payload());
    if let Some(udp) = udp {
        if filter_port(udp.get_source(), udp.get_destination(), capture_options) {
            print!("[{}] [{}]", capture_info.capture_no, capture_info.datatime);
            println!("[IPv4, {}:{} -> {}:{}, UDP, Length {}]"
            , packet.get_source()
            , udp.get_source()
            , packet.get_destination()
            , udp.get_destination()
            , udp.payload().len());
        }
    }
}

/// UDP Handler for IPV6

/// UDP Handler for IPV4
fn udp_handler_v6(
    packet: &pnet::packet::ipv6::Ipv6Packet,
    capture_options: &PacketCaptureOptions,
    capture_info: CaptureInfo
) {
    let udp = pnet::packet::udp::UdpPacket::new(packet.payload());
    if let Some(udp) = udp {
        if filter_port(udp.get_source(), udp.get_destination(), capture_options) {
            print!("[{}] [{}]", capture_info.capture_no, capture_info.datatime);
            println!("[IPv6, {}:{} -> {}:{}, UDP, Length {}]"
            , packet.get_source()
            , udp.get_source()
            , packet.get_destination()
            , udp.get_destination()
            , udp.payload().len());
        }
    }
}


/// ICMP Handler for IPV4
fn icmp_handler(
    packet: &pnet::packet::ipv4::Ipv4Packet,
    _capture_options: &PacketCaptureOptions,
    capture_info: CaptureInfo
) {
    if let Some(icmp) = pnet::packet::icmp::IcmpPacket::new(packet.payload()) {
        print!("[{}] [{}]", capture_info.capture_no, capture_info.datatime);
        println!("[IPv4, {} -> {}, ICMP {} {:?}, Length {}]"
        , packet.get_source()
        , packet.get_destination()
        , packet::get_icmp_type_string(icmp.get_icmp_type())
        , icmp.get_icmp_code()
        , icmp.payload().len()
        );
    }
}

/// ICMP Handler for IPV6
fn icmpv6_handler(
    packet: &pnet::packet::ipv6::Ipv6Packet,
    _capture_options: &PacketCaptureOptions,
    capture_info: CaptureInfo
) {
    if let Some(icmp) = pnet::packet::icmpv6::Icmpv6Packet::new(packet.payload()) {
        print!("[{}] [{}]", capture_info.capture_no, capture_info.datatime);
        println!("[IPv6, {} -> {}, ICMPv6 {} {:?}, Length {}]"
        , packet.get_source()
        , packet.get_destination()
        , packet::get_icmpv6_type_string(icmp.get_icmpv6_type())
        , icmp.get_icmpv6_code()
        , icmp.payload().len()
        );
    }
}

fn filter_host(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    capture_options: &PacketCaptureOptions
) -> bool {
    let local_host = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    if capture_options.src_ip == local_host && capture_options.dst_ip == local_host {
        return true;
    }
    if src_ip == capture_options.src_ip || dst_ip == capture_options.dst_ip {
        return true;
    } else {
        return false;
    }
}

fn filter_port(
    src_port: u16,
    dst_port: u16,
    capture_options: &PacketCaptureOptions
) -> bool {
    if capture_options.src_port == 0 && capture_options.dst_port == 0 {
        return true;
    }
    if src_port == capture_options.src_port  || dst_port == capture_options.dst_port {
        return true;
    } else {
        return false;
    }
}

fn filter_protocol(
    protocol: &str,
    capture_options: &PacketCaptureOptions
) -> bool {
    if capture_options.protocol.len() == 0 || capture_options.protocol.contains(&protocol.to_string()) {
        return true;
    } else {
        return false;
    }
}