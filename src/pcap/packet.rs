use std::borrow::Cow;
use std::io::{BufReader, Read, Write};
use std::mem;

use byteorder::{BigEndian, ByteOrder, LittleEndian, WriteBytesExt};
use nom::*;

use errors::{Error, PcapError, Result};

#[derive(Clone, Debug)]
pub struct Packet<'a> {
    pub header: Header,
    pub payload: Cow<'a, [u8]>,
}

impl<'a> Packet<'a> {
    pub fn size(&self) -> usize {
        Header::size() + self.payload.len()
    }

    pub fn parse(buf: &'a [u8], endianness: Endianness) -> Result<(&'a [u8], Packet<'a>)> {
        parse_packet(buf, endianness).map_err(|err| PcapError::from(err).into())
    }
}

#[derive(Clone, Debug)]
pub struct Header {
    /// timestamp seconds
    pub ts_sec: u32,
    /// timestamp microseconds
    pub ts_usec: u32,
    /// number of octets of packet saved in file
    pub incl_len: u32,
    /// actual length of packet
    pub orig_len: u32,
}

impl Header {
    pub fn size() -> usize {
        mem::size_of::<Self>()
    }

    pub fn parse(buf: &[u8], endianness: Endianness) -> Result<(&[u8], Self)> {
        parse_packet_header(buf, endianness).map_err(|err| PcapError::from(err).into())
    }
}

named_args!(pub parse_packet<'a>(endianness: Endianness)<&'a [u8], Packet<'a>>,
    do_parse!(
        header: apply!(parse_packet_header, endianness) >>
        payload: take!(header.incl_len) >>
        (
            Packet{
                header,
                payload: payload.into(),
            }
        )
    )
);

named_args!(pub parse_packet_header(endianness: Endianness)<Header>,
    do_parse!(
        ts_sec: u32!(endianness) >>
        ts_usec: u32!(endianness) >>
        incl_len: u32!(endianness) >>
        orig_len: u32!(endianness) >>
        (
            Header{
                ts_sec,
                ts_usec,
                incl_len,
                orig_len,
            }
        )
    )
);

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

pub trait ReadPacketExt<'a> {
    fn read_packet(&mut self, endianness: Endianness) -> Result<Packet<'a>>;
}

impl<'a, R: Read> ReadPacketExt<'a> for BufReader<R> {
    fn read_packet(&mut self, endianness: Endianness) -> Result<Packet<'a>> {
        let mut buf = vec![0; Header::size()];

        self.read_exact(&mut buf)?;

        let (_, packet_header) = Header::parse(&buf, endianness)?;

        let mut payload = vec![0; packet_header.incl_len as usize];

        self.read_exact(&mut payload)?;

        Ok(Packet {
            header: packet_header,
            payload: payload.into(),
        })
    }
}

impl<'a> ReadPacketExt<'a> for &'a [u8] {
    fn read_packet(&mut self, endianness: Endianness) -> Result<Packet<'a>> {
        let (remaining, packet) =
            parse_packet(self, endianness).map_err(|err| Error::from(PcapError::from(err)))?;

        *self = remaining;

        Ok(packet)
    }
}

pub trait WritePacketExt {
    fn write_packet<T: ByteOrder, B: AsRef<[u8]>>(
        &mut self,
        header: &Header,
        payload: B,
    ) -> Result<usize>;
}

impl<W: Write + ?Sized> WritePacketExt for W {
    fn write_packet<T: ByteOrder, B: AsRef<[u8]>>(
        &mut self,
        header: &Header,
        payload: B,
    ) -> Result<usize> {
        self.write_u32::<T>(header.ts_sec)?;
        self.write_u32::<T>(header.ts_usec)?;
        self.write_u32::<T>(header.incl_len)?;
        self.write_u32::<T>(header.orig_len)?;

        let header_len = mem::size_of::<Header>();
        let payload_len = self.write(payload.as_ref())?;

        Ok(header_len + payload_len)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    pub fn test_layout() {
        assert_eq!(Header::size(), 16)
    }
}
