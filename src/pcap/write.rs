use std::cmp;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::time::UNIX_EPOCH;

use byteorder::{ByteOrder, NativeEndian};

use errors::Result;
use pcap::{
    FileHeader, LinkType, Packet, PacketHeader, WriteHeaderExt, WritePacket, WritePacketExt,
};

pub fn create<P: AsRef<Path>, W>(path: P) -> Result<Builder<BufWriter<File>>> {
    let f = File::create(path)?;
    let w = BufWriter::new(f);

    Ok(Builder::new(w))
}

pub struct Builder<W> {
    w: Writer<W>,
}

impl<W> Builder<W> {
    pub fn new(w: W) -> Self {
        Builder {
            w: Writer {
                w,
                file_header: FileHeader::default(),
            },
        }
    }

    pub fn utc_offset_seconds(&mut self, utc_offset_secs: i32) -> &mut Self {
        self.w.file_header.thiszone = utc_offset_secs;
        self
    }

    pub fn snapshot_length(&mut self, snaplen: u32) -> &mut Self {
        self.w.file_header.snaplen = snaplen;
        self
    }

    pub fn link_type(&mut self, link_type: LinkType) -> &mut Self {
        self.w.file_header.network = link_type as u32;
        self
    }
}

impl<W> Builder<W>
where
    W: Write,
{
    pub fn build(mut self) -> Result<Writer<W>> {
        self.w.w.write_header::<NativeEndian>(&self.w.file_header)?;

        Ok(self.w)
    }
}

pub struct Writer<W> {
    w: W,
    file_header: FileHeader,
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
