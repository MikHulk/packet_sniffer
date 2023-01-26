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
            value: value,
            fragment: !(2 & value) == 2,
            more_fragment: (6 & value) == 4,
            last_fragment: (6 & value) == 0,
        }
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
