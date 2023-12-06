use std::fmt;

pub struct TcpFlags {
    pub value: u16,
    pub ns: bool,
    pub cwr: bool,
    pub ece: bool,
    pub urg: bool,
    pub ack: bool,
    pub psh: bool,
    pub rst: bool,
    pub syn: bool,
    pub fin: bool,
}

impl TcpFlags {
    pub fn new(value: u16) -> TcpFlags {
        TcpFlags {
            value,
            ns: (2_u16.pow(8) & value) == 2_u16.pow(8),
            cwr: (2_u16.pow(7) & value) == 2_u16.pow(7),
            ece: (2_u16.pow(6) & value) == 2_u16.pow(6),
            urg: (2_u16.pow(5) & value) == 2_u16.pow(5),
            ack: (2_u16.pow(4) & value) == 2_u16.pow(4),
            psh: (2_u16.pow(3) & value) == 2_u16.pow(3),
            rst: (2_u16.pow(2) & value) == 2_u16.pow(2),
            syn: (2_u16.pow(1) & value) == 2_u16.pow(1),
            fin: (2_u16.pow(0) & value) == 2_u16.pow(0),
        }
    }
}

impl fmt::Display for TcpFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut flags_repr = Vec::<&str>::new();
        if self.ns {
            flags_repr.push("NS");
        }
        if self.cwr {
            flags_repr.push("CWR");
        }
        if self.ece {
            flags_repr.push("ECE");
        }
        if self.urg {
            flags_repr.push("URG");
        }
        if self.ack {
            flags_repr.push("ACK");
        }
        if self.psh {
            flags_repr.push("PSH");
        }
        if self.rst {
            flags_repr.push("RST");
        }
        if self.syn {
            flags_repr.push("SYN");
        }
        if self.fin {
            flags_repr.push("FIN");
        }
        write!(f, "{}", flags_repr.join(", "))
    }
}
