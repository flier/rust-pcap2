use std::fs::File;
use std::io::{BufWriter, Write};
use std::ops::{Deref, DerefMut};
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
    w: W,
    file_header: FileHeader,
}

impl<W> Builder<W> {
    pub fn new(w: W) -> Self {
        Builder {
            w,
            file_header: FileHeader::default(),
        }
    }

    pub fn link_type(&mut self, link_type: LinkType) -> &mut Self {
        self.file_header.network = link_type as u32;
        self
    }
}

impl<W> Builder<W>
where
    W: Write,
{
    pub fn build(mut self) -> Result<Writer<W>> {
        self.w.write_header::<NativeEndian>(&self.file_header)?;

        Ok(Writer { w: self.w })
    }
}

pub struct Writer<W> {
    w: W,
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

impl<'a, W: Write + ?Sized> WritePacketExt<'a, Packet<'a>> for W {
    fn write_packet<T: ByteOrder>(&mut self, packet: &Packet<'a>) -> Result<usize> {
        let d = packet.timestamp.duration_since(UNIX_EPOCH)?;

        let packet_header = PacketHeader {
            ts_sec: d.as_secs() as u32,
            ts_usec: d.subsec_nanos() as u32,
            incl_len: packet.payload.len() as u32,
            orig_len: packet.actual_length as u32,
        };

        self.write_packet_data::<T, _>(&packet_header, &packet.payload)
    }
}
