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

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::packet::ipv4;
    use pnet::util::MacAddr;

    fn build_raw_packet<'a>(packet: &'a ipv4::Ipv4, buffer: &'a mut [u8]) {
        let mut raw_packet =
            ipv4::MutableIpv4Packet::new(buffer).expect("could not create MutableIpv4Packet");
        raw_packet.set_version(packet.version);
        raw_packet.set_header_length(packet.header_length);
        raw_packet.set_dscp(packet.dscp);
        raw_packet.set_ecn(packet.ecn);
        raw_packet.set_total_length(packet.total_length);
        raw_packet.set_identification(packet.identification);
        raw_packet.set_flags(packet.flags);
        raw_packet.set_fragment_offset(packet.fragment_offset);
        raw_packet.set_ttl(packet.ttl);
        raw_packet.set_next_level_protocol(packet.next_level_protocol);
        raw_packet.set_source(packet.source);
        raw_packet.set_destination(packet.destination);
        raw_packet.set_payload(&packet.payload);
        let checksum = ipv4::checksum(&raw_packet.to_immutable());
        raw_packet.set_checksum(checksum);
    }

    #[test]
    fn test_ether_type_filter() {
        let ip4 = EtherTypeFilter {
            ethertype: EtherTypes::Ipv4,
        };
        let ip6 = EtherTypeFilter {
            ethertype: EtherTypes::Ipv6,
        };
        let ip4_frame = Ethernet {
            destination: MacAddr::new(1, 1, 1, 1, 1, 1),
            source: MacAddr::new(1, 1, 1, 1, 1, 2),
            ethertype: EtherTypes::Ipv4,
            payload: Vec::<u8>::new(),
        };
        let ip6_frame = Ethernet {
            destination: MacAddr::new(1, 1, 1, 1, 1, 1),
            source: MacAddr::new(1, 1, 1, 1, 1, 2),
            ethertype: EtherTypes::Ipv6,
            payload: Vec::<u8>::new(),
        };
        println!(
            "test ip4 frame from {} to {}",
            ip4_frame.source, ip4_frame.destination
        );
        assert!(ip4.filter(ip4_frame.clone()).is_some());
        assert!(ip6.filter(ip4_frame.clone()).is_none());
        println!(
            "test ip6 frame from {} to {}",
            ip6_frame.source, ip6_frame.destination
        );
        assert!(ip4.filter(ip6_frame.clone()).is_none());
        assert!(ip6.filter(ip6_frame.clone()).is_some());
    }

    #[test]
    fn test_ether_type_filter_keeps_payload() {
        let ip4 = EtherTypeFilter {
            ethertype: EtherTypes::Ipv4,
        };
        let ip4_frame = Ethernet {
            destination: MacAddr::new(1, 1, 1, 1, 1, 1),
            source: MacAddr::new(1, 1, 1, 1, 1, 2),
            ethertype: EtherTypes::Ipv4,
            payload: vec![1, 2, 3],
        };
        let result = ip4.filter(ip4_frame.clone());
        assert!(result.is_some());
        let frame = result.unwrap();
        assert_eq!(frame.destination, ip4_frame.destination);
        assert_eq!(frame.source, ip4_frame.source);
        assert_eq!(frame.payload, ip4_frame.payload);
        assert_eq!(frame.ethertype, ip4_frame.ethertype);
    }

    #[test]
    fn test_ip_src_filter() {
        let ipsrc = IpSrcFilter {
            ips: vec![
                Ipv4Addr::new(1, 0, 0, 1),
                Ipv4Addr::new(127, 0, 0, 1),
                Ipv4Addr::new(192, 168, 0, 1),
                Ipv4Addr::new(196, 160, 10, 1),
            ],
        };
        let ok_packets: Vec<_> = ipsrc
            .ips
            .iter()
            .map(|ip| ipv4::Ipv4 {
                version: 4,
                header_length: 5,
                dscp: 0,
                ecn: 0,
                total_length: 25,
                identification: 0,
                flags: 2,
                fragment_offset: 0,
                ttl: 10,
                next_level_protocol: IpNextHeaderProtocols::Test1,
                checksum: 0,
                source: *ip,
                destination: Ipv4Addr::new(1, 0, 0, 2),
                options: vec![],
                payload: vec![1, 2, 3, 4, 5],
            })
            .collect();
        for ok_packet in ok_packets.iter() {
            let mut buffer: [u8; 25] = [0; 25];
            build_raw_packet(&ok_packet, &mut buffer);
            let ip4_frame = Ethernet {
                destination: MacAddr::new(1, 1, 1, 1, 1, 1),
                source: MacAddr::new(1, 1, 1, 1, 1, 2),
                ethertype: EtherTypes::Ipv4,
                payload: buffer.to_vec(),
            };
            let result = ipsrc.filter(ip4_frame.clone());
            assert!(result.is_some());
            let frame = result.unwrap();
            assert_eq!(frame.destination, ip4_frame.destination);
            assert_eq!(frame.source, ip4_frame.source);
            assert_eq!(frame.payload, ip4_frame.payload);
            assert_eq!(frame.ethertype, ip4_frame.ethertype);
            let packet = Ipv4Packet::new(&frame.payload).unwrap().from_packet();
            println!("packet from {} to {}", packet.source, packet.destination);
            assert!(ipsrc.ips.contains(&packet.source));
        }

        let same_nw_wrong_host = ipv4::Ipv4 {
            version: 4,
            header_length: 5,
            dscp: 0,
            ecn: 0,
            total_length: 25,
            identification: 0,
            flags: 2,
            fragment_offset: 0,
            ttl: 10,
            next_level_protocol: IpNextHeaderProtocols::Test1,
            checksum: 0,
            source: Ipv4Addr::new(192, 168, 0, 2),
            destination: Ipv4Addr::new(1, 0, 0, 2),
            options: vec![],
            payload: vec![1, 2, 3, 4, 5],
        };
        let mut buffer: [u8; 25] = [0; 25];
        build_raw_packet(&same_nw_wrong_host, &mut buffer);
        let ip4_frame = Ethernet {
            destination: MacAddr::new(1, 1, 1, 1, 1, 1),
            source: MacAddr::new(1, 1, 1, 1, 1, 2),
            ethertype: EtherTypes::Ipv4,
            payload: buffer.to_vec(),
        };
        let result = ipsrc.filter(ip4_frame.clone());
        assert!(result.is_none());

        let wrong_nw = ipv4::Ipv4 {
            version: 4,
            header_length: 5,
            dscp: 0,
            ecn: 0,
            total_length: 25,
            identification: 0,
            flags: 2,
            fragment_offset: 0,
            ttl: 10,
            next_level_protocol: IpNextHeaderProtocols::Test1,
            checksum: 0,
            source: Ipv4Addr::new(195, 168, 0, 2),
            destination: Ipv4Addr::new(1, 0, 0, 2),
            options: vec![],
            payload: vec![1, 2, 3, 4, 5],
        };
        let mut buffer: [u8; 25] = [0; 25];
        build_raw_packet(&wrong_nw, &mut buffer);
        let ip4_frame = Ethernet {
            destination: MacAddr::new(1, 1, 1, 1, 1, 1),
            source: MacAddr::new(1, 1, 1, 1, 1, 2),
            ethertype: EtherTypes::Ipv4,
            payload: buffer.to_vec(),
        };
        let result = ipsrc.filter(ip4_frame.clone());
        assert!(result.is_none());

        let reversed = ipv4::Ipv4 {
            version: 4,
            header_length: 5,
            dscp: 0,
            ecn: 0,
            total_length: 25,
            identification: 0,
            flags: 2,
            fragment_offset: 0,
            ttl: 10,
            next_level_protocol: IpNextHeaderProtocols::Test1,
            checksum: 0,
            destination: Ipv4Addr::new(192, 168, 0, 1),
            source: Ipv4Addr::new(1, 0, 0, 2),
            options: vec![],
            payload: vec![1, 2, 3, 4, 5],
        };
        let mut buffer: [u8; 25] = [0; 25];
        build_raw_packet(&reversed, &mut buffer);
        let ip4_frame = Ethernet {
            destination: MacAddr::new(1, 1, 1, 1, 1, 1),
            source: MacAddr::new(1, 1, 1, 1, 1, 2),
            ethertype: EtherTypes::Ipv4,
            payload: buffer.to_vec(),
        };
        let result = ipsrc.filter(ip4_frame.clone());
        assert!(result.is_none());
    }

    #[test]
    fn test_ip_dst_filter() {
        let ipdst = IpDstFilter {
            ips: vec![
                Ipv4Addr::new(1, 0, 0, 1),
                Ipv4Addr::new(127, 0, 0, 1),
                Ipv4Addr::new(192, 168, 0, 1),
                Ipv4Addr::new(196, 160, 10, 1),
            ],
        };
        let ok_packets: Vec<_> = ipdst
            .ips
            .iter()
            .map(|ip| ipv4::Ipv4 {
                version: 4,
                header_length: 5,
                dscp: 0,
                ecn: 0,
                total_length: 25,
                identification: 0,
                flags: 2,
                fragment_offset: 0,
                ttl: 10,
                next_level_protocol: IpNextHeaderProtocols::Test1,
                checksum: 0,
                source: Ipv4Addr::new(1, 0, 0, 2),
                destination: *ip,
                options: vec![],
                payload: vec![1, 2, 3, 4, 5],
            })
            .collect();
        for ok_packet in ok_packets.iter() {
            let mut buffer: [u8; 25] = [0; 25];
            build_raw_packet(&ok_packet, &mut buffer);
            let ip4_frame = Ethernet {
                destination: MacAddr::new(1, 1, 1, 1, 1, 1),
                source: MacAddr::new(1, 1, 1, 1, 1, 2),
                ethertype: EtherTypes::Ipv4,
                payload: buffer.to_vec(),
            };
            let result = ipdst.filter(ip4_frame.clone());
            assert!(result.is_some());
            let frame = result.unwrap();
            assert_eq!(frame.destination, ip4_frame.destination);
            assert_eq!(frame.source, ip4_frame.source);
            assert_eq!(frame.payload, ip4_frame.payload);
            assert_eq!(frame.ethertype, ip4_frame.ethertype);
            let packet = Ipv4Packet::new(&frame.payload).unwrap().from_packet();
            println!("packet from {} to {}", packet.source, packet.destination);
            assert!(ipdst.ips.contains(&packet.destination));
        }

        let same_nw_wrong_host = ipv4::Ipv4 {
            version: 4,
            header_length: 5,
            dscp: 0,
            ecn: 0,
            total_length: 25,
            identification: 0,
            flags: 2,
            fragment_offset: 0,
            ttl: 10,
            next_level_protocol: IpNextHeaderProtocols::Test1,
            checksum: 0,
            destination: Ipv4Addr::new(192, 168, 0, 2),
            source: Ipv4Addr::new(1, 0, 0, 2),
            options: vec![],
            payload: vec![1, 2, 3, 4, 5],
        };
        let mut buffer: [u8; 25] = [0; 25];
        build_raw_packet(&same_nw_wrong_host, &mut buffer);
        let ip4_frame = Ethernet {
            destination: MacAddr::new(1, 1, 1, 1, 1, 1),
            source: MacAddr::new(1, 1, 1, 1, 1, 2),
            ethertype: EtherTypes::Ipv4,
            payload: buffer.to_vec(),
        };
        let result = ipdst.filter(ip4_frame.clone());
        assert!(result.is_none());

        let wrong_nw = ipv4::Ipv4 {
            version: 4,
            header_length: 5,
            dscp: 0,
            ecn: 0,
            total_length: 25,
            identification: 0,
            flags: 2,
            fragment_offset: 0,
            ttl: 10,
            next_level_protocol: IpNextHeaderProtocols::Test1,
            checksum: 0,
            destination: Ipv4Addr::new(195, 168, 0, 2),
            source: Ipv4Addr::new(1, 0, 0, 2),
            options: vec![],
            payload: vec![1, 2, 3, 4, 5],
        };
        let mut buffer: [u8; 25] = [0; 25];
        build_raw_packet(&wrong_nw, &mut buffer);
        let ip4_frame = Ethernet {
            destination: MacAddr::new(1, 1, 1, 1, 1, 1),
            source: MacAddr::new(1, 1, 1, 1, 1, 2),
            ethertype: EtherTypes::Ipv4,
            payload: buffer.to_vec(),
        };
        let result = ipdst.filter(ip4_frame.clone());
        assert!(result.is_none());

        let reversed = ipv4::Ipv4 {
            version: 4,
            header_length: 5,
            dscp: 0,
            ecn: 0,
            total_length: 25,
            identification: 0,
            flags: 2,
            fragment_offset: 0,
            ttl: 10,
            next_level_protocol: IpNextHeaderProtocols::Test1,
            checksum: 0,
            source: Ipv4Addr::new(192, 168, 0, 1),
            destination: Ipv4Addr::new(1, 0, 0, 2),
            options: vec![],
            payload: vec![1, 2, 3, 4, 5],
        };
        let mut buffer: [u8; 25] = [0; 25];
        build_raw_packet(&reversed, &mut buffer);
        let ip4_frame = Ethernet {
            destination: MacAddr::new(1, 1, 1, 1, 1, 1),
            source: MacAddr::new(1, 1, 1, 1, 1, 2),
            ethertype: EtherTypes::Ipv4,
            payload: buffer.to_vec(),
        };
        let result = ipdst.filter(ip4_frame.clone());
        assert!(result.is_none());
    }
}
