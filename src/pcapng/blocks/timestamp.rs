use std::io::{Read, Write};
use std::mem;

use byteorder::{ByteOrder, ReadBytesExt, WriteBytesExt};

use errors::Result;

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

pub trait WriteTimestamp {
    fn write_timestamp<T: ByteOrder>(&mut self, ts: Timestamp) -> Result<usize>;
}

impl<W: Write + ?Sized> WriteTimestamp for W {
    fn write_timestamp<T: ByteOrder>(&mut self, ts: Timestamp) -> Result<usize> {
        self.write_u32::<T>(hi(ts))?;
        self.write_u32::<T>(lo(ts))?;

        Ok(mem::size_of::<u32>() * 2)
    }
}
