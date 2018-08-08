use pcapng::blocks::{EnhancedPacket, ObsoletedPacket, SimplePacket};

pub enum Packet<'a> {
    Simple(SimplePacket<'a>),
    Enhanced(EnhancedPacket<'a>),
    Obsoleted(ObsoletedPacket<'a>),
}
