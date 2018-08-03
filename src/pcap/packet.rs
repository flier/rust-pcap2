use std::borrow::Cow;
use std::io::{BufReader, Read, Write};
use std::mem;
use std::ops::{Deref, DerefMut};

use byteorder::{BigEndian, ByteOrder, LittleEndian, WriteBytesExt};
use nom::*;

use errors::{Error, PcapError, Result};

#[derive(Clone, Debug)]
pub struct Packet<'a> {
    pub header: Header,
    pub payload: Cow<'a, [u8]>,
}

impl<'a> Deref for Packet<'a> {
    type Target = Header;

    fn deref(&self) -> &Self::Target {
        &self.header
    }
}

impl<'a> DerefMut for Packet<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.header
    }
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

pub trait WritePacket {
    fn write_packet_data<T: ByteOrder, B: AsRef<[u8]>>(
        &mut self,
        header: &Header,
        payload: B,
    ) -> Result<usize>;
}

pub trait WritePacketExt<'a, P>: WritePacket {
    fn write_packet<T: ByteOrder>(&mut self, packet: &P) -> Result<usize>;

    fn write_packets<T: ByteOrder, I: IntoIterator<Item = P>>(&mut self, iter: I) -> Result<usize> {
        let mut wrote = 0;

        for packet in iter {
            wrote += self.write_packet::<T>(&packet)?;
        }

        Ok(wrote)
    }
}

impl<W: Write + ?Sized> WritePacket for W {
    fn write_packet_data<T: ByteOrder, B: AsRef<[u8]>>(
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

impl<'a, W: Write + ?Sized> WritePacketExt<'a, Packet<'a>> for W {
    fn write_packet<T: ByteOrder>(&mut self, packet: &Packet<'a>) -> Result<usize> {
        self.write_packet_data::<T, _>(&packet.header, &packet.payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use pcap::tests::PACKETS;
    use pcap::FileHeader;

    #[test]
    pub fn test_layout() {
        assert_eq!(Header::size(), 16)
    }

    #[test]
    pub fn test_parse_packet() {
        for (buf, magic) in PACKETS.iter() {
            let mut remaining = &buf[FileHeader::size()..];

            let packet = remaining.read_packet(magic.endianness()).unwrap();

            assert!(remaining.is_empty());
            assert_eq!(packet.ts_sec, 0x56506e1a);
            assert_eq!(packet.ts_usec, 0x182b0ad0);
            assert_eq!(packet.incl_len, 4);
            assert_eq!(packet.orig_len, 60);
            assert_eq!(packet.payload, Cow::from(&[0x44u8, 0x41, 0x54, 0x41][..]));
        }
    }

    #[test]
    pub fn test_read_packet() {
        for (buf, magic) in PACKETS.iter() {
            let mut reader = BufReader::new(&buf[FileHeader::size()..]);

            let packet = reader.read_packet(magic.endianness()).unwrap();

            assert!(reader.get_ref().is_empty());
            assert_eq!(packet.ts_sec, 0x56506e1a);
            assert_eq!(packet.ts_usec, 0x182b0ad0);
            assert_eq!(packet.incl_len, 4);
            assert_eq!(packet.orig_len, 60);
            assert_eq!(packet.payload, Cow::from(&[0x44u8, 0x41, 0x54, 0x41][..]));
        }
    }

    #[test]
    pub fn test_write_packet() {
        for (buf, magic) in PACKETS.iter() {
            let packet = Packet {
                header: Header {
                    ts_sec: 0x56506e1a,
                    ts_usec: 0x182b0ad0,
                    incl_len: 4,
                    orig_len: 60,
                },
                payload: Cow::from(&[0x44u8, 0x41, 0x54, 0x41][..]),
            };
            let packet_len = packet.size();

            let mut data = vec![];
            let wrote = match magic.endianness() {
                Endianness::Little => data.write_packet::<LittleEndian>(&packet),
                Endianness::Big => data.write_packet::<BigEndian>(&packet),
            }.unwrap();

            assert_eq!(wrote, packet_len);
            assert_eq!(data.as_slice(), &buf[FileHeader::size()..]);
        }
    }
}
