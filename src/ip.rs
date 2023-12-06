use pnet::packet::ethernet::{EtherTypes, Ethernet};
use pnet::packet::ipv4::Ipv4;
use pnet::packet::ipv4::Ipv4Packet;

use crate::pnet::packet::FromPacket;

use std::fmt;

pub struct Ipv4Flags {
    pub value: u8,
    pub fragment: bool,
    pub more_fragment: bool,
    pub last_fragment: bool,
}

impl Ipv4Flags {
    pub fn new(value: u8) -> Ipv4Flags {
        Ipv4Flags {
            value,
            fragment: !(2 & value) == 2,
            more_fragment: (6 & value) == 4,
            last_fragment: (6 & value) == 0,
        }
    }
}

pub fn unwrap_packet(frame: &Ethernet) -> Option<Ipv4> {
    if frame.ethertype == EtherTypes::Ipv4 {
        Some(Ipv4Packet::new(&frame.payload).unwrap().from_packet())
    } else {
        None
    }
}

impl fmt::Display for Ipv4Flags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.fragment {
            write!(f, "DON'T FRAGMENT")
        } else if self.last_fragment {
            write!(f, "LAST FRAGMENT")
        } else {
            write!(f, "MORE FRAGMENT")
        }
    }
}
