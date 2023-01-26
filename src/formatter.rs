use crate::ip::Ipv4Flags;
use crate::tcp::TcpFlags;
use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherTypes, Ethernet};
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::icmp::{Icmp, IcmpTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::FromPacket;

pub trait Formatter {
    fn format(&self, frame: &Ethernet) -> Option<String>;
}

fn get_pretty_icmp_name(packet: Icmp) -> String {
    let message = match packet.icmp_type {
        IcmpTypes::EchoReply => format!("reply({}, {})", packet.icmp_type.0, packet.icmp_code.0),
        IcmpTypes::EchoRequest => {
            format!("request({}, {})", packet.icmp_type.0, packet.icmp_code.0)
        }
        IcmpTypes::DestinationUnreachable => {
            let icmp_code = match packet.icmp_code.0 {
                0 => "Destination network unreachable",
                1 => "Destination host unreachable",
                2 => "Destination protocol unreachable",
                3 => "Destination port unreachable",
                4 => "Fragmentation required, and DF flag set",
                5 => "Source route failed",
                6 => "Destination network unknown",
                7 => "Destination host unknown",
                8 => "Source host isolated",
                9 => "Network administratively prohibited",
                10 => "Host administratively prohibited",
                11 => "Network unreachable for ToS",
                12 => "Host unreachable for ToS",
                13 => "Communication administratively prohibited",
                14 => "Host Precedence Violation",
                15 => "Precedence cutoff in effect",
                _ => "Unreachable with unknonwn code",
            };
            format!(
                "{}({}, {})",
                icmp_code, packet.icmp_type.0, packet.icmp_code.0
            )
        }
        _ => format!("unknown({}, {})", packet.icmp_type.0, packet.icmp_code.0),
    };
    format!("{}", message)
}

pub struct IcmpFormatter {}

impl Formatter for IcmpFormatter {
    fn format(&self, frame: &Ethernet) -> Option<String> {
        if frame.ethertype == EtherTypes::Ipv4 {
            let packet = Ipv4Packet::new(&frame.payload).unwrap().from_packet();
            if packet.next_level_protocol == IpNextHeaderProtocols::Icmp {
                if let Some(icmp_packet) = IcmpPacket::new(&packet.payload) {
                    let icmp_struct = icmp_packet.from_packet();
                    Some(format!(
                        "ICMP {}: {} -> {}",
                        get_pretty_icmp_name(icmp_struct),
                        packet.source,
                        packet.destination
                    ))
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        }
    }
}

pub struct TcpFormatter {}

impl Formatter for TcpFormatter {
    fn format(&self, frame: &Ethernet) -> Option<String> {
        if frame.ethertype == EtherTypes::Ipv4 {
            let packet = Ipv4Packet::new(&frame.payload).unwrap().from_packet();
            if packet.next_level_protocol == IpNextHeaderProtocols::Tcp {
                if let Some(tcp_packet) = TcpPacket::new(&packet.payload) {
                    let tcp_struct = tcp_packet.from_packet();
                    Some(format!(
                        "TCP seq: {}, {}:{} -> {}:{}, {} bytes\n\
                         \tIP flags: {}({:0>3b})\n\
                         \tTCP flags: {}({:0>9b})",
                        tcp_struct.sequence,
                        packet.source,
                        tcp_struct.source,
                        packet.destination,
                        tcp_struct.destination,
                        packet.total_length,
                        Ipv4Flags::new(packet.flags),
                        packet.flags,
                        TcpFlags::new(tcp_struct.flags),
                        tcp_struct.flags,
                    ))
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        }
    }
}

pub struct Ipv4Formatter {}

impl Formatter for Ipv4Formatter {
    fn format(&self, frame: &Ethernet) -> Option<String> {
        if frame.ethertype == EtherTypes::Ipv4 {
            let packet = Ipv4Packet::new(&frame.payload).unwrap().from_packet();
            Some(format!(
                "{}: {} -> {}, {} bytes\n\tflags: {}({:0>3b})",
                packet.next_level_protocol,
                packet.source,
                packet.destination,
                packet.total_length,
                Ipv4Flags::new(packet.flags),
                packet.flags
            ))
        } else {
            None
        }
    }
}

pub struct ArpFormatter {}

impl Formatter for ArpFormatter {
    fn format(&self, frame: &Ethernet) -> Option<String> {
        if frame.ethertype == EtherTypes::Arp {
            let packet = ArpPacket::new(&frame.payload).unwrap().from_packet();
            Some(format!(
                "ARP {:?}: {} / {} -> {} / {}",
                packet.operation,
                packet.sender_hw_addr,
                packet.sender_proto_addr,
                packet.target_hw_addr,
                packet.target_proto_addr,
            ))
        } else {
            None
        }
    }
}

pub struct PipelineFormatter {
    pub pipeline: Vec<Box<dyn Formatter>>,
}

impl Formatter for PipelineFormatter {
    fn format(&self, frame: &Ethernet) -> Option<String> {
        for formatter in self.pipeline.iter() {
            if let Some(format) = formatter.format(frame) {
                return Some(format);
            }
        }
        None
    }
}
