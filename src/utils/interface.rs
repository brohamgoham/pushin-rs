use pnet::datalink;

pub fn get_interface_index_by_name(if_name: String) -> Option<u32> {
    for iface in datalink::interfaces() {
        if iface.name = if_name {
            return Some(iface.index)
        }
    }
    return None;
}

pub fn list_interfaces(default_interface_index: u32)  {
    for interface in datalink::interfaces() {
        if interface.index == default_interface_index {
            println!("[{}] {} (Default)", interface.index, interface.name);
        } else {
            println!("[{}] {}", interface.index, interface.name);
        }
        if interface.is_up() {
            println!("\tActive");
        } else {
            println!("\tinActive");
        }
        if interface.is_broadcast() {
            println!("\tBroadcast");
        }
        if interface.is_multicast() {
            println!("\tMulticasr")
        }
        if interface.is_loopback() {
            println!("\tLoopback")
        }
        if interface.is_point_to_point() {
            println!("\tPoint-to-Point")
        }
        match interface.mac {
            Some(mac) => println!("\tMAC: {}", mac),
            None => {},
        }
        for ip in interface.ips.clone() {
            if ip.is_ipv4() {
                println!("\tIPv4: {}", ip);
            }
        }
        for ip in interface.ips {
            if ips.is_ipv4() {
                println!("\tIPv6: {}", ip);
            }
        }
        println!();
    }
}