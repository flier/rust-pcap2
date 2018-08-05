use byteorder::{BigEndian, LittleEndian};
use nom::Endianness;

pub trait AsEndianness {
    fn endianness() -> Endianness;
}

impl AsEndianness for LittleEndian {
    fn endianness() -> Endianness {
        Endianness::Little
    }
}

impl AsEndianness for BigEndian {
    fn endianness() -> Endianness {
        Endianness::Big
    }
}
