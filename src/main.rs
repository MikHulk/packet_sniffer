#[macro_use]
extern crate clap;
extern crate pnet;
mod filter;
mod formatter;
mod ip;
mod tcp;

use std::process;

use pnet::datalink::Channel;
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::FromPacket;

use filter::{build_ip_filter, FrameFilter};
use formatter::{
    ArpFormatter, Formatter, IcmpFormatter, Ipv4Formatter, PipelineFormatter, TcpFormatter,
    UdpFormatter,
};

fn main() {
    let matches = clap_app!(
        packet_sniffer =>
            (version: "1.0.0")
            (author: "Mickaël Viey. <m.viey@wanadoo.fr>")
            (about: "A light packet sniffer")
            (@arg IFACE: +required "Interface to sniff")
            (@arg IPSRC: -s --ipsrc +multiple +takes_value "keep packets originated from this ip")
            (@arg PTSRC: -p --srcport +multiple +takes_value "keep packets originated from this port")
            (@arg IPDST: -d --ipdst +multiple +takes_value "keep packets going towards this ip")
            (@arg PROTO: -t --ethtype +takes_value "keep ethernet frame with this type.")
    )
    .get_matches();

    let interface_name = matches.value_of("IFACE").unwrap();
    let interface_names_match = |iface: &NetworkInterface| iface.name == interface_name;

    let interfaces = datalink::interfaces();

    let interface = match interfaces.into_iter().find(interface_names_match) {
        Some(iface) => iface,
        None => {
            eprintln!("unknown interface");
            process::exit(1);
        }
    };

    let pipeline = match build_ip_filter(matches) {
        Ok(filter) => filter,
        Err(reason) => {
            eprintln!("{}", reason);
            process::exit(2);
        }
    };

    let formatter = PipelineFormatter {
        pipeline: vec![
            Box::new(TcpFormatter {}),
            Box::new(UdpFormatter {}),
            Box::new(IcmpFormatter {}),
            Box::new(Ipv4Formatter {}),
            Box::new(ArpFormatter {}),
        ],
    };

    let (mut _tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {
            eprintln!("Unhandled channel type");
            process::exit(3);
        }
        Err(e) => {
            eprintln!(
                "An error occurred when creating the datalink channel: {}",
                e
            );
            process::exit(3);
        }
    };

    loop {
        match rx.next() {
            Ok(frame) => {
                let frame = EthernetPacket::new(frame).unwrap().from_packet();
                if let Some(frame) = pipeline.filter(frame) {
                    match formatter.format(&frame) {
                        Some(result) => println!("{}", result),
                        None => {
                            println!("{}: {:?}", frame.ethertype, frame);
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("An error occurred while reading: {}", e);
                process::exit(4);
            }
        }
    }
}
