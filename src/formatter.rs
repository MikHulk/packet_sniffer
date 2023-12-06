use crate::ip::{unwrap_packet, Ipv4Flags};
use crate::tcp::TcpFlags;
use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherTypes, Ethernet};
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::icmp::{Icmp, IcmpTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::FromPacket;

pub trait Formatter {
    fn format(&self, frame: &Ethernet) -> Option<String>;
}

fn get_pretty_icmp_name(packet: Icmp) -> String {
    match packet.icmp_type {
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
    }
}

pub struct IcmpFormatter {}

impl Formatter for IcmpFormatter {
    fn format(&self, frame: &Ethernet) -> Option<String> {
        if let Some(packet) = unwrap_packet(frame) {
            if packet.next_level_protocol == IpNextHeaderProtocols::Icmp {
                if let Some(icmp_packet) = IcmpPacket::new(&packet.payload) {
                    let icmp_struct = icmp_packet.from_packet();
                    return Some(format!(
                        "ICMP {}: {} -> {}",
                        get_pretty_icmp_name(icmp_struct),
                        packet.source,
                        packet.destination
                    ));
                }
            }
        }
        None
    }
}

fn hexdump(v: Vec<u8>) -> String {
    fn format_ascii(i: u8) -> char {
        if i.is_ascii() && !i.is_ascii_control() {
            i as char
        } else {
            '.'
        }
    }
    let mut dump = String::new();
    let mut it = v.iter();
    while let Some(i) = it.next() {
        let mut ascii = String::new();
        let mut values = String::new();
        values += &format!("{:3} ", i);
        ascii += &format!("{}", format_ascii(*i));
        for _ in 0..16 {
            match it.next() {
                Some(i) => {
                    values += &format!("{:3} ", i);
                    ascii += &format!("{}", format_ascii(*i));
                }
                None => {
                    values += "    ";
                    ascii += " ";
                }
            }
        }
        dump += &(values + "  " + &ascii + "\n")
    }
    dump
}

pub struct TcpFormatter {}

impl Formatter for TcpFormatter {
    fn format(&self, frame: &Ethernet) -> Option<String> {
        if let Some(packet) = unwrap_packet(frame) {
            if packet.next_level_protocol == IpNextHeaderProtocols::Tcp {
                if let Some(tcp_packet) = TcpPacket::new(&packet.payload) {
                    let tcp_struct = tcp_packet.from_packet();
                    return Some(format!(
                        "TCP seq: {}, {}:{} -> {}:{}, {} bytes\n\
                         \tIP flags: {}({:0>3b})\n\
                         \tTCP flags: {}({:0>9b})\n{}",
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
                        hexdump(tcp_struct.payload),
                    ));
                }
            }
        }
        None
    }
}

pub struct UdpFormatter {}

impl Formatter for UdpFormatter {
    fn format(&self, frame: &Ethernet) -> Option<String> {
        if let Some(packet) = unwrap_packet(frame) {
            if packet.next_level_protocol == IpNextHeaderProtocols::Udp {
                if let Some(udp_packet) = UdpPacket::new(&packet.payload) {
                    let udp_struct = udp_packet.from_packet();
                    return Some(format!(
                        "UDP: {}:{} -> {}:{}, {} bytes\n\
                         \tIP flags: {}({:0>3b})\n{}",
                        packet.source,
                        udp_struct.source,
                        packet.destination,
                        udp_struct.destination,
                        packet.total_length,
                        Ipv4Flags::new(packet.flags),
                        packet.flags,
                        hexdump(udp_struct.payload),
                    ));
                }
            }
        }
        None
    }
}

pub struct Ipv4Formatter {}

impl Formatter for Ipv4Formatter {
    fn format(&self, frame: &Ethernet) -> Option<String> {
        if let Some(packet) = unwrap_packet(frame) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hexdump() {
        let some_data: Vec<u8> = (0..311).map(|i| i as u8).collect();
        let result = hexdump(some_data);
        println!("{}", result);
        let expected = "  \
           0   1   2   3   4   5   6   7   8   9  10  11  12  13  14  15  16   .................\n \
          17  18  19  20  21  22  23  24  25  26  27  28  29  30  31  32  33   ............... !\n \
          34  35  36  37  38  39  40  41  42  43  44  45  46  47  48  49  50   \"#$%&'()*+,-./012\n \
          51  52  53  54  55  56  57  58  59  60  61  62  63  64  65  66  67   3456789:;<=>?@ABC\n \
          68  69  70  71  72  73  74  75  76  77  78  79  80  81  82  83  84   DEFGHIJKLMNOPQRST\n \
          85  86  87  88  89  90  91  92  93  94  95  96  97  98  99 100 101   UVWXYZ[\\]^_`abcde\n\
         102 103 104 105 106 107 108 109 110 111 112 113 114 115 116 117 118   fghijklmnopqrstuv\n\
         119 120 121 122 123 124 125 126 127 128 129 130 131 132 133 134 135   wxyz{|}~.........\n\
         136 137 138 139 140 141 142 143 144 145 146 147 148 149 150 151 152   .................\n\
         153 154 155 156 157 158 159 160 161 162 163 164 165 166 167 168 169   .................\n\
         170 171 172 173 174 175 176 177 178 179 180 181 182 183 184 185 186   .................\n\
         187 188 189 190 191 192 193 194 195 196 197 198 199 200 201 202 203   .................\n\
         204 205 206 207 208 209 210 211 212 213 214 215 216 217 218 219 220   .................\n\
         221 222 223 224 225 226 227 228 229 230 231 232 233 234 235 236 237   .................\n\
         238 239 240 241 242 243 244 245 246 247 248 249 250 251 252 253 254   .................\n\
         255   0   1   2   3   4   5   6   7   8   9  10  11  12  13  14  15   .................\n \
          16  17  18  19  20  21  22  23  24  25  26  27  28  29  30  31  32   ................ \n \
          33  34  35  36  37  38  39  40  41  42  43  44  45  46  47  48  49   !\"#$%&'()*+,-./01\n \
          50  51  52  53  54                                                   23456            \n\
         ";
        println!("{}", expected);
        assert_eq!(expected, result);
    }
}
