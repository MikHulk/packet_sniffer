use std::net::Ipv4Addr;

use crate::pnet::packet::FromPacket;
use pnet::packet::ethernet::{EtherType, EtherTypes, Ethernet};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;

pub trait FrameFilter {
    fn filter(&self, frame: Ethernet) -> Option<Ethernet>;
}

pub struct EtherTypeFilter {
    pub ethertype: EtherType,
}

impl FrameFilter for EtherTypeFilter {
    fn filter(&self, frame: Ethernet) -> Option<Ethernet> {
        if frame.ethertype == self.ethertype {
            Some(frame)
        } else {
            None
        }
    }
}

pub struct IpSrcFilter {
    pub ips: Vec<Ipv4Addr>,
}

impl FrameFilter for IpSrcFilter {
    fn filter(&self, frame: Ethernet) -> Option<Ethernet> {
        if frame.ethertype == EtherTypes::Ipv4 {
            let packet = Ipv4Packet::new(&frame.payload).unwrap();
            if self.ips.iter().any(|ip| packet.get_source() == *ip) {
                Some(frame)
            } else {
                None
            }
        } else {
            Some(frame)
        }
    }
}

pub struct TcpUdpPortFilter {
    pub ports: Vec<u16>,
}

impl FrameFilter for TcpUdpPortFilter {
    fn filter(&self, frame: Ethernet) -> Option<Ethernet> {
        if frame.ethertype == EtherTypes::Ipv4 {
            let packet = Ipv4Packet::new(&frame.payload).unwrap().from_packet();
            if packet.next_level_protocol == IpNextHeaderProtocols::Tcp {
                if let Some(tcp_packet) = TcpPacket::new(&packet.payload) {
                    let tcp_struct = tcp_packet.from_packet();
                    if self
                        .ports
                        .iter()
                        .any(|p| tcp_struct.destination == *p || tcp_struct.source == *p)
                    {
                        Some(frame)
                    } else {
                        None
                    }
                } else {
                    Some(frame)
                }
            } else if packet.next_level_protocol == IpNextHeaderProtocols::Udp {
                if let Some(udp_packet) = UdpPacket::new(&packet.payload) {
                    let udp_struct = udp_packet.from_packet();
                    if self
                        .ports
                        .iter()
                        .any(|p| udp_struct.destination == *p || udp_struct.source == *p)
                    {
                        Some(frame)
                    } else {
                        None
                    }
                } else {
                    Some(frame)
                }
            } else {
                None
            }
        } else {
            None
        }
    }
}

pub struct IpDstFilter {
    pub ips: Vec<Ipv4Addr>,
}

impl FrameFilter for IpDstFilter {
    fn filter(&self, frame: Ethernet) -> Option<Ethernet> {
        if frame.ethertype == EtherTypes::Ipv4 {
            let packet = Ipv4Packet::new(&frame.payload).unwrap();
            if self.ips.iter().any(|ip| packet.get_destination() == *ip) {
                Some(frame)
            } else {
                None
            }
        } else {
            Some(frame)
        }
    }
}

pub struct PipelineFilter {
    pub pipeline: Vec<Box<dyn FrameFilter>>,
}

impl FrameFilter for PipelineFilter {
    fn filter(&self, frame: Ethernet) -> Option<Ethernet> {
        match self
            .pipeline
            .iter()
            .try_fold(frame, |frame, filter| filter.filter(frame).ok_or(0))
        {
            Ok(frame) => Some(frame),
            Err(_) => None,
        }
    }
}

fn get_ether_types(name: &str) -> Option<EtherType> {
    match name {
        "aarp" => Some(EtherTypes::Aarp),
        "appletalk" => Some(EtherTypes::AppleTalk),
        "arp" => Some(EtherTypes::Arp),
        "cfm" => Some(EtherTypes::Cfm),
        "cobra" => Some(EtherTypes::CobraNet),
        "dec" => Some(EtherTypes::DECnet),
        "flowcontrol" => Some(EtherTypes::FlowControl),
        "ipv4" => Some(EtherTypes::Ipv4),
        "ipv6" => Some(EtherTypes::Ipv6),
        "ipx" => Some(EtherTypes::Ipx),
        "lldp" => Some(EtherTypes::Lldp),
        "mpls" => Some(EtherTypes::Mpls),
        "mplsmcast" => Some(EtherTypes::MplsMcast),
        "pbridge" => Some(EtherTypes::PBridge),
        "ppoedisc" => Some(EtherTypes::PppoeDiscovery),
        "pppoesess" => Some(EtherTypes::PppoeSession),
        "ptp" => Some(EtherTypes::Ptp),
        "qinq" => Some(EtherTypes::QinQ),
        "qnx" => Some(EtherTypes::Qnx),
        "rarp" => Some(EtherTypes::Rarp),
        "trill" => Some(EtherTypes::Trill),
        "vlan" => Some(EtherTypes::Vlan),
        "wol" => Some(EtherTypes::WakeOnLan),
        _ => None,
    }
}

pub fn build_ip_filter(app: clap::ArgMatches) -> Result<PipelineFilter, String> {
    let mut pipeline: Vec<Box<dyn FrameFilter>> = Vec::new();

    if let Some(protoname) = app.value_of("PROTO") {
        if let Some(proto) = get_ether_types(protoname) {
            pipeline.push(Box::new(EtherTypeFilter { ethertype: proto }))
        }
    };

    if let Some(ip_it) = app.values_of("IPSRC") {
        if ip_it
            .clone()
            .map(|ip| ip.parse::<Ipv4Addr>())
            .all(|ip| ip.is_ok())
        {
            pipeline.push(Box::new(IpSrcFilter {
                ips: ip_it.map(|ip| ip.parse::<Ipv4Addr>().unwrap()).collect(),
            }))
        } else {
            return Err(format!("ip src {:?} bad format", ip_it.collect::<Vec<_>>()));
        }
    };

    if let Some(port_it) = app.values_of("PTSRC") {
        let parsing = port_it.clone().map(|p| p.parse::<u16>());
        if parsing.clone().all(|res| res.is_ok()) {
            pipeline.push(Box::new(TcpUdpPortFilter {
                ports: parsing.map(|res| res.unwrap()).collect(),
            }))
        } else {
            return Err(format!(
                "port dst {:?} bad format",
                port_it.collect::<Vec<_>>()
            ));
        }
    };

    if let Some(ip_it) = app.values_of("IPDST") {
        if ip_it
            .clone()
            .map(|ip| ip.parse::<Ipv4Addr>())
            .all(|ip| ip.is_ok())
        {
            pipeline.push(Box::new(IpDstFilter {
                ips: ip_it.map(|ip| ip.parse::<Ipv4Addr>().unwrap()).collect(),
            }))
        } else {
            return Err(format!("ip dst {:?} bad format", ip_it.collect::<Vec<_>>()));
        }
    };

    Ok(PipelineFilter { pipeline })
}
