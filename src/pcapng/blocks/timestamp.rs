use std::io::{Read, Write};
use std::mem;

use byteorder::{ByteOrder, ReadBytesExt, WriteBytesExt};

use errors::Result;
use traits::WriteTo;

pub type Timestamp = u64;

pub fn hi(ts: Timestamp) -> u32 {
    (ts >> 32) as u32
}

pub fn lo(ts: Timestamp) -> u32 {
    ts as u32
}

pub fn new(hi: u32, lo: u32) -> Timestamp {
    (u64::from(hi) << 32) + u64::from(lo)
}

pub trait ReadTimestamp {
    fn read_timestamp<T: ByteOrder>(&mut self) -> Result<Timestamp>;
}

impl<R: Read + ?Sized> ReadTimestamp for R {
    fn read_timestamp<T: ByteOrder>(&mut self) -> Result<Timestamp> {
        let hi = self.read_u32::<T>()?;
        let lo = self.read_u32::<T>()?;

        Ok(new(hi, lo))
    }
}

impl WriteTo for Timestamp {
    fn write_to<T: ByteOrder, W: Write>(&self, w: &mut W) -> Result<usize> {
        w.write_u32::<T>(hi(*self))?;
        w.write_u32::<T>(lo(*self))?;

        Ok(mem::size_of::<u32>() * 2)
    }
}
