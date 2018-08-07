use std::borrow::Cow;
use std::cmp;
use std::io::Write;
use std::mem;

use byteorder::{ByteOrder, WriteBytesExt};
use nom::*;

use errors::{PcapError, Result};
use pcapng::options::pad_to;
use pcapng::Block;

pub const BLOCK_TYPE: u32 = 0x0000_0003;

/// The Simple Packet Block (SPB) is a lightweight container for storing the packets coming from the network.
#[derive(Clone, Debug, PartialEq)]
pub struct SimplePacket<'a> {
    /// actual length of the packet when it was transmitted on the network.
    pub original_len: u32,
    /// the data coming from the network, including link-layer headers.
    pub data: Cow<'a, [u8]>,
}

impl<'a> SimplePacket<'a> {
    pub fn block_type() -> u32 {
        BLOCK_TYPE
    }

    pub fn size(&self) -> usize {
        mem::size_of::<u32>() + pad_to::<u32>(self.data.len())
    }

    pub fn parse(buf: &'a [u8], endianness: Endianness) -> Result<(&'a [u8], Self)> {
        parse_simple_packet(buf, endianness).map_err(|err| PcapError::from(err).into())
    }
}

///     0                   1                   2                   3
///     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///    +---------------------------------------------------------------+
///  0 |                    Block Type = 0x00000003                    |
///    +---------------------------------------------------------------+
///  4 |                      Block Total Length                       |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  8 |                    Original Packet Length                     |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// 12 /                                                               /
///    /                          Packet Data                          /
///    /              variable length, padded to 32 bits               /
///    /                                                               /
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    |                      Block Total Length                       |
///    +---------------------------------------------------------------+
named_args!(parse_simple_packet(endianness: Endianness)<SimplePacket>,
    dbg_dmp!(do_parse!(
        original_len: u32!(endianness) >>
        data: rest >>
        (
            SimplePacket {
                original_len,
                data: Cow::from(&data[..cmp::min(original_len as usize, data.len())]),
            }
        )
    ))
);

pub trait WriteSimplePacket {
    fn write_simple_packet<'a, T: ByteOrder>(&mut self, packet: &SimplePacket<'a>)
        -> Result<usize>;
}

impl<W: Write + ?Sized> WriteSimplePacket for W {
    fn write_simple_packet<'a, T: ByteOrder>(
        &mut self,
        packet: &SimplePacket<'a>,
    ) -> Result<usize> {
        self.write_u32::<T>(packet.original_len)?;
        self.write_all(&packet.data)?;
        let padded_len = pad_to::<u32>(packet.data.len()) - packet.data.len();
        if padded_len > 0 {
            self.write_all(&vec![0; padded_len])?;
        }

        Ok(packet.size())
    }
}

impl<'a> Block<'a> {
    pub fn as_simple_packet(&'a self, endianness: Endianness) -> Option<SimplePacket<'a>> {
        if self.ty == SimplePacket::block_type() {
            SimplePacket::parse(&self.body, endianness)
                .map(|(_, packet)| packet)
                .map_err(|err| {
                    warn!("fail to parse simple packet: {:?}", err);

                    hexdump!(self.body);

                    err
                })
                .ok()
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use byteorder::LittleEndian;

    use super::*;
    use pcapng::Block;

    pub const LE_SIMPLE_PACKET: &[u8] = b"\x03\x00\x00\x00\
\x54\x00\x00\x00\
\x42\x00\x00\x00\
\x8C\x85\x90\x0B\xCB\x9E\x20\x4E\x71\xFC\x92\x14\x08\x00\x45\x00\
\x00\x34\xE8\xA8\x40\x00\xEF\x06\xC1\x0B\x11\xA7\xC0\x80\x0A\x06\
\x05\xE2\x01\xBB\xC8\xF3\x0A\x30\x41\xDC\xD0\x4D\x17\xA5\x80\x10\
\x01\x3F\xC7\xDC\x00\x00\x01\x01\x05\x0A\xD0\x4D\x17\xA4\xD0\x4D\
\x17\xA5\x00\x00\
\x54\x00\x00\x00";

    lazy_static! {
        static ref SIMPLE_PACKET: SimplePacket<'static> = SimplePacket {
            original_len: 66,
            data: Cow::from(
                &b"\x8C\x85\x90\x0B\xCB\x9E\x20\x4E\x71\xFC\x92\x14\x08\x00\x45\x00\
\x00\x34\xE8\xA8\x40\x00\xEF\x06\xC1\x0B\x11\xA7\xC0\x80\x0A\x06\
\x05\xE2\x01\xBB\xC8\xF3\x0A\x30\x41\xDC\xD0\x4D\x17\xA5\x80\x10\
\x01\x3F\xC7\xDC\x00\x00\x01\x01\x05\x0A\xD0\x4D\x17\xA4\xD0\x4D\
\x17\xA5"[..]
            ),
        };
    }

    #[test]
    fn test_parse() {
        let (remaining, block) = Block::parse(LE_SIMPLE_PACKET, Endianness::Little).unwrap();

        assert_eq!(remaining, b"");
        assert_eq!(block.ty, BLOCK_TYPE);
        assert_eq!(block.len as usize, LE_SIMPLE_PACKET.len());

        let simple_packet = block.as_simple_packet(Endianness::Little).unwrap();

        assert_eq!(simple_packet, *SIMPLE_PACKET);
    }

    #[test]
    fn test_write() {
        let mut buf = vec![];

        let wrote = buf.write_simple_packet::<LittleEndian>(&SIMPLE_PACKET.clone())
            .unwrap();

        assert_eq!(wrote, SIMPLE_PACKET.size());
        assert_eq!(
            buf.as_slice(),
            &LE_SIMPLE_PACKET[8..LE_SIMPLE_PACKET.len() - 4]
        );
    }
}
