use pnet::datalink;

fn main() {
    // Get a vector with all network interfaces found
    let all_interfaces = datalink::interfaces();

    for iface in all_interfaces.iter() {
        match iface.mac {
            Some(mac_addr) => println!("{:15}:\t{}", iface.name, mac_addr),
            None => println!("{:15}", iface.name),
        }
        if iface.is_loopback() {
            print!("LOOPBACK ");
        }
        if iface.is_multicast() {
            print!("MULTICAST ");
        }
        if iface.is_broadcast() {
            print!("BROADCAST ");
        }
        if iface.is_point_to_point() {
            print!("P2P ");
        }
        if iface.is_up() {
            println!("UP");
        } else {
            println!("DOWN");
        }
        for ip_addr in iface.ips.iter() {
            println!("\t{}", ip_addr);
        }
        println!("{:04}, 0x{:x}", iface.index, iface.flags);
    }
}
