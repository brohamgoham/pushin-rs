use std::net::IpAddr;
use std::str::FromStr;
use super::interface;
use super::db;

pub fn validate_interface(v: String) -> Result<> {
    match interface::get_interface_index_by_name(v) {
        Some(_) => {
            Ok(())
        },
        None => {
            Err(String::from("Invalid network interface nane"))
        },
    }
}

pub fn validate_host_opt(v: String) -> Result<(), String> {
    let addr = IpAddr::from_str(&v);
    match addr {
        Ok(_) => {
            return Ok(())
        },
        Err(_) => {
            return Err(String::from("Please specify Ip Addr"));
        }
    }
}

/// .
///
/// # Errors
///
pub fn validate_port_opt(v: String) -> Result<(), String> {
    match v.parse::<u16>() {
        Ok(_) => {
            return Ok(())
        },
        Err(_) => {
            return Err(String::from("Please Specify port number!!"));
        }
    }
}

pub fn validate_duration_opt(v: String) -> Result<(), String> {
    match v.parse::<u64>() {
        Ok(_) => {
            return Ok(())
        },
        Err(_) => {
            return Err(String::from("Please specific port number"));
        }
    }
}

pub fn validate_protocol(v: String) -> Result<(), String> {
    let validate_protocol = db::get_protocol_list();
    let protocol_vec: Vec<&str> = v.trim().split(",").collect();
    for protocol in protocol_vec {
        if !validate_protocol.contains(&protocol.to_string()) {
            return Err(String::from("Invalid protocol"));
        }
    }
    Ok(())
}

pub fn validate_host_port(v: String) -> Result<(), String> {
    let host_valid = match validate_host_opt(v.clone()) {
        Ok(_) => true,
        Err(_) => false,
    };
    let port_valid = match validate_port_opt(v) {
        Ok(_) => true, 
        Err(_) => false,
    };
    if host_valid || port_valid {
        Ok(())
    } else {
        Err(String::from("Please specify Ip Address or port Number!!"))
    }
}

