pub const PDUMP_PROTOCOLS: &str = include_str!("../../data/pdump-protocols.txt");
 
pub fn get_protocol_list() -> Vec<String> {
    let rs: Vec<&str> = PDUMP_PROTOCOLS.trim().split("\n").collect();
    let mut protocol_vec: Vec<String> = vec![];
    for r in rs {
        let row: Vec<&str> = r.trim().split(",").collect();
        if row.len() > 0 {
            protocol_vec.push(row[0].to_string());
        }
    }
    return protocol_vec;
}