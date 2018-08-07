use std::io::Write;

use byteorder::{BigEndian, ByteOrder, LittleEndian};
use nom::Endianness;

use errors::Result;

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

pub trait WriteTo {
    fn write_to<T: ByteOrder, W: Write>(&self, w: &mut W) -> Result<usize>;
}
