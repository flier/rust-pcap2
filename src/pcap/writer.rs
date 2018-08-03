use std::cmp;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::ops::{Deref, DerefMut};
use std::path::Path;
use std::time::UNIX_EPOCH;

use byteorder::{ByteOrder, NativeEndian};

use errors::Result;
use pcap::{
    AsEndianness, FileHeader, LinkType, Packet, PacketHeader, WriteHeaderExt, WritePacket,
    WritePacketExt,
};

pub fn create<P: AsRef<Path>, W>(path: P) -> Result<Builder<BufWriter<File>>> {
    let f = File::create(path)?;
    let w = BufWriter::new(f);

    Ok(Builder::new::<NativeEndian>(w))
}

pub struct Builder<W> {
    w: Writer<W>,
}

impl<W> Builder<W> {
    pub fn new<T: AsEndianness>(w: W) -> Self {
        Builder {
            w: Writer {
                w,
                file_header: FileHeader::new::<T>(),
            },
        }
    }

    #[must_use]
    pub fn utc_offset_seconds(mut self, utc_offset_secs: i32) -> Self {
        self.w.file_header.thiszone = utc_offset_secs;
        self
    }

    #[must_use]
    pub fn snapshot_length(mut self, snaplen: u32) -> Self {
        self.w.file_header.snaplen = snaplen;
        self
    }

    #[must_use]
    pub fn link_type(mut self, link_type: LinkType) -> Self {
        self.w.file_header.network = link_type as u32;
        self
    }
}

impl<W> Builder<W>
where
    W: Write,
{
    #[must_use]
    pub fn build<T: ByteOrder>(mut self) -> Result<Writer<W>> {
        self.w.w.write_header::<T>(&self.w.file_header)?;

        Ok(self.w)
    }
}

pub struct Writer<W> {
    w: W,
    file_header: FileHeader,
}

impl<W> Writer<W> {
    pub fn into_inner(self) -> W {
        self.w
    }
}

impl<W> Deref for Writer<W> {
    type Target = W;

    fn deref(&self) -> &Self::Target {
        &self.w
    }
}

impl<W> DerefMut for Writer<W> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.w
    }
}

impl<W> WritePacket for Writer<W>
where
    W: Write,
{
    fn write_packet_data<T: ByteOrder, B: AsRef<[u8]>>(
        &mut self,
        header: &PacketHeader,
        payload: B,
    ) -> Result<usize> {
        self.w.write_packet_data::<T, _>(header, payload)
    }
}

impl<'a, W> WritePacketExt<'a, Packet<'a>> for Writer<W>
where
    W: Write,
{
    fn write_packet<T: ByteOrder>(&mut self, packet: &Packet<'a>) -> Result<usize> {
        let d = packet.timestamp.duration_since(UNIX_EPOCH)?;

        let incl_len = cmp::min(packet.payload.len() as u32, self.file_header.snaplen);
        let payload = &packet.payload[..incl_len as usize];

        let packet_header = PacketHeader {
            ts_sec: d.as_secs() as u32,
            ts_usec: d.subsec_nanos() as u32, // always use nanosecond resolution
            incl_len,
            orig_len: packet.actual_length as u32,
        };

        self.write_packet_data::<T, _>(&packet_header, &payload)
    }
}
#[cfg(test)]
mod test {
    use std::borrow::Cow;
    use std::iter::once;
    use std::time::Duration;

    use nom::Endianness;

    use byteorder::{BigEndian, LittleEndian};

    use super::*;
    use pcap::tests::NANO_PACKETS;

    #[test]
    pub fn test_write_packets() {
        for (buf, magic) in NANO_PACKETS.iter() {
            let packet = Packet {
                timestamp: UNIX_EPOCH + Duration::new(0x56506e1a, 0x182b0ad0),
                actual_length: 60,
                payload: Cow::from(&[0x44u8, 0x41, 0x54, 0x41][..]),
            };

            let mut data = vec![];
            let mut writer = match magic.endianness() {
                Endianness::Little => Builder::new::<LittleEndian>(data)
                    .link_type(LinkType::RAW)
                    .build::<LittleEndian>(),
                Endianness::Big => Builder::new::<BigEndian>(data)
                    .link_type(LinkType::RAW)
                    .build::<BigEndian>(),
            }.unwrap();

            let wrote = match magic.endianness() {
                Endianness::Little => writer.write_packets::<LittleEndian, _>(once(packet)),
                Endianness::Big => writer.write_packets::<BigEndian, _>(once(packet)),
            }.unwrap();

            assert_eq!(FileHeader::size() + wrote, buf.len());
            assert_eq!(writer.as_slice(), *buf);
        }
    }
}
