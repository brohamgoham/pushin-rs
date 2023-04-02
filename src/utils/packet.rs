use pnet::packet::ethernet::{EtherType, EtherTypes};
use pnet::packet::icmp::{IcmpType, IcmpTypes};
use pnet::packet::icmpv6::{Icmpv6Type, Icmpv6Types};
use pnet::packet::tcp::TcpFlags;

pub fn get_ethertype_string(ethertype: EtherType) -> String {
    match ethertype {
        EtherTypes::Aarp => {return String::from("AARP");},
    }
}
