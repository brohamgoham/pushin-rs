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