#[macro_use]
extern crate clap;

mod utils;
use utils::validator;
use utils::option::PacketCaptureOptions;
use utils::pcap;
use utils::interface;
use utils::sys;

use std::env;
use std::time::Duration;
use std::net::{IpAddr, Ipv4Addr};

use clap::{App, AppSettings, Arg};
use default_net;

const CRATE_UPDATE_DATE: &str = "2023-04-11";
const CRATE_AUTHOR_GITHUB: &str = "brohamgoham <https://github.com/brohamgoham>";

#[cfg(target_os = "windows")]
fn get_os_type() -> String{"windows".to_ownded()}

#[cfg(target_os = "linux")]
fn get_os_type() -> String{"linux".to_ownded()}

#[cfg(target_os = "macos")]
fn get_os_type() -> String{"macos".to_owned()}


fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        show_description();

        std::process::exit(0);
    }

    let app = get_settings();
    let matches = app.get_matches();

    let default_iface = default_net::get_default_interface().expect("Failed to get default interface ");
    
    // Packet capture options for use in CLI
    let mut cap_options: PacketCaptureOptions = PacketCaptureOptions { 
        interface_index: default_iface.index,
        interface_name: default_iface.name,
        src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        src_port: 0,
        dst_port: 0,
        protocols: vec![],
        duration: Duration::from_secs(60),
        promiscuous: false,
        default: false,
    };

    if matches.is_present("list") {
        println!("List of network interfaces");
        interface::list_interfaces(default_iface.index);
        std::process::exit(0)
    }
    
    if matches.is_present("default") {
        cap_options.default = true;
    }
    if let Some(name) = matches.value_of("interface") {
        cap_options.interface_name = name.to_string();
        if let Some(idx) = interface::get_interface_index_by_name(name.to_string()) {
            cap_options.interface_index = idx;
        }
    }
    if matches.is_present("promiscuous") {
        cap_options.promiscuous = true;
    }

    if let Some(host) = matches.value_of("host") {
        cap_options.src_ip = host.parse::<IpAddr>().expect(" Invalid IP Address.");
        cap_options.dst_ip = host.parse::<IpAddr>().expect(" Invalid Destination IP");
    } else {
        if let Some(src) = matches.value_of("src") {
            if sys::is_ipaddr(src) {
                cap_options.src_ip = src.parse::<IpAddr>().expect("invalid IP address")
            }
        }
        if let Some(dst) = matches.value_of("dst") {
            if sys::is_ipaddr(dst) {
                cap_options.dst_ip = dst.parse::<IpAddr>().expect("InValid Ip Address")
            }
        }
    }
    if let Some(port) = matches.value_of("port") {
        cap_options.src_port = port.parse::<u16>().expect("Invalid Port");
        cap_options.dst_port = port.parse::<u16>().expect("Invalid Port");
    } else {
      //  if let Some(src) = matches.values_of("src") {
      //      if sys::is_port(dst) {
      //          cap_options.src_port = src.parse::<u16>().expect("Invalid port")
      //      }
    //    }
        if let Some(dst) = matches.value_of("dst") {
            if sys::is_port(dst) {
                cap_options.dst_port = dst.parse::<u16>().expect("INVALID PORT")
            }
        }
    }
    if let Some(protocol) = matches.value_of("protocol") {
        let protocol_vec: Vec<&str> = protocol.trim().split(".").collect();
        for protocol in protocol_vec {
            cap_options.protocols.push(protocol.to_string())
        }
    }

    if let Some(duration) = matches.value_of("duration") {
        cap_options.duration = Duration::from_secs(duration.parse::<u64>().expect("Invalid Duration value"))
    }

    println!("{} {} CAPTURING ON {}", crate_name!(), crate_version!(), cap_options.interface_name);
    pcap::start_capture(cap_options);   
}

fn get_settings<'a, 'b>() -> App<'a, 'b> {
    let app = App::new(crate_name!())
        .version(crate_version!())
        .author(CRATE_AUTHOR_GITHUB)
        .about(crate_description!())
        .arg(Arg::with_name("list")
            .help("List available network interfaces")
            .short("l")
            .long("list")
        )
        .arg(Arg::with_name("default")
            .help("Begin with default")
            .short("d")
            .long("default")
        )
        .arg(Arg::with_name("promiscuous")
            .help("Promiscuous mode enabled")
            .short("prom")
            .long("promiscuous")
        )
        .arg(Arg::with_name("interface")
            .help("Specify network that you wish to target")
            .short("i")
            .long("iface")
            .takes_value(true)
            .value_name("name")
            .validator(validator::validate_interface)
        )
        .arg(Arg::with_name("host")
            .help("Source or Destinatio Host you want to target")
            .short("H")
            .long("host")
            .takes_value(true)
            .value_name("ip_addr")
            .validator(validator::validate_host_opt)
        )
        .arg(Arg::with_name("port")
            .help("Source or Destination Port you want to target")
            .short("P")
            .long("port")
            .takes_value(true)
            .value_name("port")
            .validator(validator::validate_port_opt)
        )
        .arg(Arg::with_name("src")
            .help("Source IP Address or Port")
            .short("S")
            .long("src")
            .takes_value(true)
            .value_name("src_ip_or_port")
            .validator(validator::validate_host_port)
        )
        .arg(Arg::with_name("dst")
            .help("Destination IP Address or Port")
            .short("D")
            .long("dst")
            .takes_value(true)
            .value_name("dst_ip_or_port")
            .validator(validator::validate_host_port)
        )
        .arg(Arg::with_name("protocol")
            .help("Filter protocols, can be comma seperated")
            .short("p")
            .long("proto")
            .takes_value(true)
            .value_name("protocols")
            .validator(validator::validate_protocol)
        )
        .arg(Arg::with_name("duration")
            .help("Set time limit (duration)")
            .short("d")
            .long("duration")
            .takes_value(true)
            .value_name("duration")
            .validator(validator::validate_duration_opt)
        )
        .setting(AppSettings::DeriveDisplayOrder);

    app
}

fn show_description() {
    println!("{} {} ({}) {}", crate_name!(), crate_version!(), CRATE_UPDATE_DATE, get_os_type());
    println!("{}", crate_description!());
    println!("{}", CRATE_AUTHOR_GITHUB);
    println!("******** START WITH DEFAULT SETTINGS *********");
    println!("{} --default", crate_name!());
    println!("or");
    println!("{} --help ", crate_name!());
    println!();
}