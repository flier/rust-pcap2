use std::cmp;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::ops::{Deref, DerefMut};
use std::path::Path;
use std::time::UNIX_EPOCH;

use byteorder::{BigEndian, LittleEndian, NativeEndian};
use nom::Endianness;

use errors::Result;
use pcap::header::{AsEndianness, Header as FileHeader, LinkType, WriteHeaderExt};
use pcap::packet::{Header as PacketHeader, WritePacket};
use pcap::Packet;

/// Opens a file as a stream in write-only mode.
pub fn create<P: AsRef<Path>, W>(path: P) -> Result<Builder<BufWriter<File>>> {
    let f = File::create(path)?;
    let w = BufWriter::new(f);

    Ok(Builder::new(w))
}

/// The `Builder` struct contains the options for creating a new packet capture.
pub struct Builder<W> {
    w: Writer<W>,
}

impl<W> Builder<W> {
    /// Create a new `Builder` which can be used configure the options of a new `Writer`.
    pub fn new(w: W) -> Self {
        Self::with_byteorder::<NativeEndian>(w)
    }

    /// Create a new `Builder` with special `Endianness` which can be used configure the options of a new `Writer`.
    pub fn with_endianness(w: W, endianness: Endianness) -> Self {
        match endianness {
            Endianness::Little => Self::with_byteorder::<LittleEndian>(w),
            Endianness::Big => Self::with_byteorder::<BigEndian>(w),
        }
    }

    /// Create a new `Builder` with special `ByteOrder` which can be used configure the options of a new `Writer`.
    pub fn with_byteorder<T: AsEndianness>(w: W) -> Self {
        Builder {
            w: Writer {
                w,
                file_header: FileHeader::new::<T>(),
            },
        }
    }

    /// The correction time in seconds between GMT (UTC) and the local timezone of the following packet header timestamps.
    #[must_use]
    pub fn utc_offset_seconds(mut self, utc_offset_secs: i32) -> Self {
        self.w.file_header.thiszone = utc_offset_secs;
        self
    }

    /// The maximum size of a packet that can be written to the file.
    #[must_use]
    pub fn snapshot_length(mut self, snaplen: u32) -> Self {
        self.w.file_header.snaplen = snaplen;
        self
    }

    /// The type of packets that will be written to the file.
    ///
    /// See `Linktype` for known values.
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
    /// Build a new `Writer` that writes the packet capture data to the specified `Write`.
    #[must_use]
    pub fn build(mut self) -> Result<Writer<W>> {
        match self.w.file_header.magic().endianness() {
            Endianness::Little => {
                self.w.w.write_header::<LittleEndian>(&self.w.file_header)?;
            }
            Endianness::Big => {
                self.w.w.write_header::<BigEndian>(&self.w.file_header)?;
            }
        }

        Ok(self.w)
    }
}

/// The `Writer` struct allows writing packets as a packet capture.
pub struct Writer<W> {
    w: W,
    file_header: FileHeader,
}

impl<W> Writer<W> {
    /// Create a new `Writer` that writes the packet capture data from an iterator to the specified `Write`.
    pub fn from_iter<'a, I: IntoIterator<Item = Packet<'a>>>(iter: I) -> Result<Writer<Vec<u8>>> {
        Builder::new(vec![])
            .build()
            .and_then(|mut writer| writer.write_packets(iter).map(|_| writer))
    }

    /// Consumes this `Writer`, returning the underlying value.
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

impl<W> Writer<W>
where
    W: Write,
{
    /// Create a new `Writer` that writes the packet capture data to the specified `Write`.
    pub fn new(w: W) -> Result<Self> {
        Builder::new(w).build()
    }

    /// Write a packet to the packet capture stream.
    pub fn write_packet<'a>(&mut self, packet: &Packet<'a>) -> Result<usize> {
        let d = packet.timestamp.duration_since(UNIX_EPOCH)?;

        let incl_len = cmp::min(packet.payload.len() as u32, self.file_header.snaplen);
        let payload = &packet.payload[..incl_len as usize];

        let packet_header = PacketHeader {
            ts_sec: d.as_secs() as u32,
            ts_usec: d.subsec_nanos() as u32, // always use nanosecond resolution
            incl_len,
            orig_len: packet.actual_length as u32,
        };

        match self.file_header.magic().endianness() {
            Endianness::Little => self.w
                .write_packet_data::<LittleEndian, _>(&packet_header, &payload),
            Endianness::Big => self.w
                .write_packet_data::<BigEndian, _>(&packet_header, &payload),
        }
    }

    /// Write a packet to the packets from an iterator capture stream.
    pub fn write_packets<'a, I: IntoIterator<Item = Packet<'a>>>(
        &mut self,
        iter: I,
    ) -> Result<usize> {
        let mut wrote = 0;

        for packet in iter {
            wrote += self.write_packet(&packet)?;
        }

        Ok(wrote)
    }
}

#[cfg(test)]
mod test {
    use std::borrow::Cow;
    use std::iter::once;
    use std::time::Duration;

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
            let mut writer = Builder::with_endianness(data, magic.endianness())
                .link_type(LinkType::RAW)
                .build()
                .unwrap();
            let wrote = writer.write_packets(once(packet)).unwrap();

            assert_eq!(FileHeader::size() + wrote, buf.len());
            assert_eq!(writer.as_slice(), *buf);
        }
    }
}
