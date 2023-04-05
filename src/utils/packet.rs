use pnet::packet::ethernet::{EtherType, EtherTypes};
use pnet::packet::icmp::{IcmpType, IcmpTypes};
use pnet::packet::icmpv6::{Icmpv6Type, Icmpv6Types};
use pnet::packet::tcp::TcpFlags;

pub fn get_ethertype_string(ethertype: EtherType) -> String {
    match ethertype {
        EtherTypes::Aarp => {return String::from("RARP");},
        EtherTypes::AppleTalk => {return String::from("AppleTalk");},
        EtherTypes::Arp => {return String::from("ARP");},
        EtherTypes::Cfm => {return String::from("CFM");},
        EtherTypes::CobraNet => {return String::from("CobraNet");},
        EtherTypes::DECnet => {return String::from("DECnet");},
        EtherTypes::FlowControl => {return String::from("FlowControl");},
        EtherTypes::Ipv4 => {return String::from("IPv4");},
        EtherTypes::Ipv6 => {return String::from("IPv6");},
        EtherTypes::Ipx => {return String::from("IPX");},
        EtherTypes::Lldp => {return String::from("LLDP");},
        EtherTypes::Mpls => {return String::from("MPLS");},
        EtherTypes::MplsMcast => {return String::from("MPLS Multicast");},
        EtherTypes::PBridge => {return String::from(" Provider Bridge");},
        EtherTypes::PppoeDiscovery => {return String::from("PPPOE Discovery Stage");},
        EtherTypes::PppoeSession => {return String::from("PPPoE Session Stage");},
        EtherTypes::Ptp => {return String::from("PTP");},
        EtherTypes::QinQ => {return String::from("Q-in-Q");},
        EtherTypes::Qnx => {return String::from("QNX");},
        EtherTypes::Rarp => {return String::from("RARP");},
        EtherTypes::Trill => {return String::from("Trill");},
        EtherTypes::Vlan => {return String::from("VLAN");},
        EtherTypes::WakeOnLan => {return String::from(" Wake on Lan");},
        _ => {return String::from("Unknown");},
    }
}

pub fn get_imcp_type_string(imcptype: IcmpType) -> String {
    match imcptype {
        IcmpTypes::AddressMaskReply => {return String::from("Address Mask Reply");},
        ImcpTypes::AddressMaskRequest => {return String::from("Address Mask Request");},
        ImcpTypes::DestinationUnreachable => {return String::from("Destination Unreachable");},
        ImcpTypes::EchoReply => {return String::from("Echo Reply");},
        ImcpTypes::EchoRequest => {return String::from("Echo Request");},
        ImcpTypes::InformationReply => {return String::from("Information Reply");},
        ImcpTypes::ImformationRequest => {return String::from("Information Request");},
        ImcpTypes::ParameterProblem => {return String::("Parameter Proble");},
        ImcpTypes::RedirectMessage => {return String::from("Redirect Message");},
        ImcpTypes::RouterAdvertisement => {return String::from("Router Advertisement");},
        ImcpTypes::RouterSolicitation => {return String::from("Router Solicitiation");},
        ImcpTypes::SourceQuench => {return String::from("Source Quench");},
        ImcpTypes::TimeExceeded => {return String::from("Time Exceeded");},
        ImcpTypes::Timestamp => {return String::from("Timestamp");},
        ImcpTypes::TimestampReply => {return String::from("Timestamp Reply");},
        ImcpTypes::Traceroute => {return String::from("Traceroute");},
        _ => {return String::from("Unknown");},
    }
}

pub fn get_imcpv6_type_string(imcpv6type: Icmpv6Type) -> String {
    match imcpv6type {
        Icmpv6Types::DestinationUnreachable => {return String::from("Destination Unreachable");},
        Icmpv6Types::EchoReply => {return String::from("Echo Reply");},
        Icmpv6Types::EchoRequest => {return String::from("Echo Request");},
        Icmpv6Types::ParameterProblem => {return String::from("Parameter Problem");},
        Icmpv6Type::TimeExceeded => {returb String::from("Time Exceeded");},
        _ => {return String::from("Unknown");}
    }
}

 /// TCP flags are a low level network method
 /// We will do the ACK CWR ECE FIN NS PSH RST SYN 
 /// and URG to communiicate between packets in our target machine
 pub fn get_tcp_flags_string(tcp_flags: u16) -> String {
    match tcp_flags {
        TcpFlags::ACK => {return String::from("ACK");},
        TcpFlags::CWR => {return String::from("CWR");},
        TcpFlags::ECE => {return String::from("ECE");},
        TcpFlags::FIN => {return String::from("FIN");},
        TcpFlags::NS => {return String::from("NS");},
        TcpFlags::PSH => {return String::from("PSH");},
        TcpFlags::RST => {return String::from("RST");},
        TcpFlags::SYN => {return String::from("SYN");},
        TcpFlags::URG => {return String::from("URG");},
        // now we will do some checks to see if flags 
        // shoule be combines
        _ => {
            if tcp_flags == TcpFlags::FIN | TcpFlags::ACK {
                return String::from("FIN+ACK");
            }
            else if tcp_flags == TcpFlags::SYN | TcpFlags::ACK {
                return String::from("SYN+ACK");
            }
            else if tcp_flags == TcpFlags::RST | TcpFlags::ACK {
                return String::from("RST+ACK");
            }
            else if tcp_flags == TcpFlags::PSH | TcpFlags::ACK {
                return String::from("PSH+ACK");
            }
            else(
                return tcp_flags.to_string();
            )
        },
    }
 }