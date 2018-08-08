use std::borrow::Cow;
use std::io::Write;
use std::mem;

use byteorder::{ByteOrder, WriteBytesExt};
use nom::*;

pub use super::enhanced_packet::{
    epb_flags as pack_flags, epb_hash as pack_hash, Flags, EPB_FLAGS as PACK_FLAGS,
    EPB_HASH as PACK_HASH,
};
use super::timestamp::{self, Timestamp};
use errors::{PcapError, Result};
use pcapng::block::Block;
use pcapng::options::{pad_to, parse_options, Options};
use traits::WriteTo;

pub const BLOCK_TYPE: u32 = 0x0000_0002;

/// A Packet Block was a container for storing packets coming from the network.
#[derive(Clone, Debug, PartialEq)]
pub struct ObsoletedPacket<'a> {
    /// specifies the interface this packet comes from
    pub interface_id: u16,
    /// a local drop counter.
    pub drops_count: Option<u16>,
    /// the number of units of time that have elapsed since 1970-01-01 00:00:00 UTC.
    pub timestamp: Timestamp,
    /// number of octets captured from the packet.
    pub captured_len: u32,
    /// actual length of the packet when it was transmitted on the network.
    pub original_len: u32,
    /// the data coming from the network, including link-layer headers.
    pub data: Cow<'a, [u8]>,
    /// optionally, a list of options
    pub options: Options<'a>,
}

impl<'a> ObsoletedPacket<'a> {
    pub fn block_type() -> u32 {
        BLOCK_TYPE
    }

    pub fn size(&self) -> usize {
        self.options.iter().fold(
            mem::size_of::<u16>() * 2
                + mem::size_of::<Timestamp>()
                + mem::size_of::<u32>() * 2
                + pad_to::<u32>(self.data.len()),
            |size, opt| size + opt.size(),
        )
    }

    pub fn parse(buf: &'a [u8], endianness: Endianness) -> Result<(&'a [u8], Self)> {
        parse_obsoleted_packet(buf, endianness).map_err(|err| PcapError::from(err).into())
    }

    pub fn flags<T: ByteOrder>(&self) -> Option<Flags> {
        self.options
            .iter()
            .find(|opt| opt.code == PACK_FLAGS && opt.value.len() == mem::size_of::<u32>())
            .map(|opt| Flags::from_bits_truncate(T::read_u32(&opt.value)))
    }

    pub fn hash(&self) -> Vec<(u8, &[u8])> {
        self.options
            .iter()
            .filter(|opt| opt.code == PACK_HASH && opt.value.len() > 0)
            .map(|opt| (opt.value[0], &opt.value[1..]))
            .collect()
    }
}

///     0                   1                   2                   3
///     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///    +---------------------------------------------------------------+
///  0 |                    Block Type = 0x00000002                    |
///    +---------------------------------------------------------------+
///  4 |                      Block Total Length                       |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  8 |         Interface ID          |          Drops Count          |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// 12 |                        Timestamp (High)                       |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// 16 |                        Timestamp (Low)                        |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// 20 |                    Captured Packet Length                     |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// 24 |                    Original Packet Length                     |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// 28 /                                                               /
///    /                          Packet Data                          /
///    /              variable length, padded to 32 bits               /
///    /                                                               /
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    /                                                               /
///    /                      Options (variable)                       /
///    /                                                               /
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    |                      Block Total Length                       |
///    +---------------------------------------------------------------+
named_args!(parse_obsoleted_packet(endianness: Endianness)<ObsoletedPacket>,
    dbg_dmp!(do_parse!(
        interface_id: u16!(endianness) >>
        drops_count:  u16!(endianness) >>
        timestamp_hi: u32!(endianness) >>
        timestamp_lo: u32!(endianness) >>
        captured_len: u32!(endianness) >>
        original_len: u32!(endianness) >>
        data: take!(pad_to::<u32>(captured_len as usize)) >>
        options: apply!(parse_options, endianness) >>
        (
            ObsoletedPacket {
                interface_id,
                drops_count: if drops_count == 0xFFFF { None } else { Some(drops_count) },
                timestamp: timestamp::new(timestamp_hi, timestamp_lo),
                captured_len,
                original_len,
                data: Cow::from(&data[..captured_len as usize]),
                options,
            }
        )
    ))
);

impl<'a> WriteTo for ObsoletedPacket<'a> {
    fn write_to<T: ByteOrder, W: Write>(&self, w: &mut W) -> Result<usize> {
        w.write_u16::<T>(self.interface_id)?;
        w.write_u16::<T>(self.drops_count.unwrap_or(0xFFFF))?;
        self.timestamp.write_to::<T, _>(w)?;
        w.write_u32::<T>(self.captured_len)?;
        w.write_u32::<T>(self.original_len)?;
        w.write_all(&self.data)?;
        let padded_len = pad_to::<u32>(self.data.len()) - self.data.len();
        if padded_len > 0 {
            w.write_all(&vec![0; padded_len])?;
        }
        self.options.write_to::<T, _>(w)?;

        Ok(self.size())
    }
}

impl<'a> Block<'a> {
    pub fn as_obsoleted_packet(&'a self, endianness: Endianness) -> Option<ObsoletedPacket<'a>> {
        if self.ty == ObsoletedPacket::block_type() {
            ObsoletedPacket::parse(&self.body, endianness)
                .map(|(_, packet)| packet)
                .map_err(|err| {
                    warn!("fail to parse obsoleted packet: {:?}", err);

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
pub mod tests {
    use byteorder::LittleEndian;

    use super::*;
    use pcapng::blocks::enhanced_packet::{HASH_ALGO_CRC32, HASH_ALGO_MD5};
    use pcapng::Block;

    pub const LE_OBSOLETED_PACKET: &[u8] = b"\x02\x00\x00\x00\
\x64\x00\x00\x00\
\x00\x00\xFF\xFF\
\x6A\x72\x05\x00\xC1\x6A\x96\x80\
\x42\x00\x00\x00\
\x42\x00\x00\x00\
\x8C\x85\x90\x0B\xCB\x9E\x20\x4E\x71\xFC\x92\x14\x08\x00\x45\x00\
\x00\x34\xE8\xA8\x40\x00\xEF\x06\xC1\x0B\x11\xA7\xC0\x80\x0A\x06\
\x05\xE2\x01\xBB\xC8\xF3\x0A\x30\x41\xDC\xD0\x4D\x17\xA5\x80\x10\
\x01\x3F\xC7\xDC\x00\x00\x01\x01\x05\x0A\xD0\x4D\x17\xA4\xD0\x4D\
\x17\xA5\x00\x00\
\x64\x00\x00\x00";

    lazy_static! {
        static ref OBSOLETED_PACKET: ObsoletedPacket<'static> = ObsoletedPacket {
            interface_id: 0,
            drops_count: None,
            timestamp: 0x05726a80966ac1,
            captured_len: 66,
            original_len: 66,
            data: Cow::from(
                &b"\x8C\x85\x90\x0B\xCB\x9E\x20\x4E\x71\xFC\x92\x14\x08\x00\x45\x00\
\x00\x34\xE8\xA8\x40\x00\xEF\x06\xC1\x0B\x11\xA7\xC0\x80\x0A\x06\
\x05\xE2\x01\xBB\xC8\xF3\x0A\x30\x41\xDC\xD0\x4D\x17\xA5\x80\x10\
\x01\x3F\xC7\xDC\x00\x00\x01\x01\x05\x0A\xD0\x4D\x17\xA4\xD0\x4D\
\x17\xA5"[..]
            ),
            options: vec![],
        };
    }

    #[test]
    fn test_parse() {
        let (remaining, block) = Block::parse(LE_OBSOLETED_PACKET, Endianness::Little).unwrap();

        assert_eq!(remaining, b"");
        assert_eq!(block.ty, BLOCK_TYPE);
        assert_eq!(block.size(), LE_OBSOLETED_PACKET.len());

        let obsoleted_packet = block.as_obsoleted_packet(Endianness::Little).unwrap();

        assert_eq!(obsoleted_packet, *OBSOLETED_PACKET);
    }

    #[test]
    fn test_write() {
        let mut buf = vec![];

        let wrote = OBSOLETED_PACKET
            .write_to::<LittleEndian, _>(&mut buf)
            .unwrap();

        assert_eq!(wrote, OBSOLETED_PACKET.size());
        assert_eq!(
            buf.as_slice(),
            &LE_OBSOLETED_PACKET[8..LE_OBSOLETED_PACKET.len() - 4]
        );
    }

    #[test]
    fn test_options() {
        let packet = ObsoletedPacket {
            interface_id: 0,
            drops_count: Some(123),
            timestamp: 0,
            captured_len: 0,
            original_len: 0,
            data: Cow::from(&[][..]),
            options: vec![
                pack_flags::<LittleEndian>(Flags::INBOUND | Flags::UNICAST),
                pack_hash(HASH_ALGO_CRC32, [0xEC, 0x1D, 0x87, 0x97]),
                pack_hash(
                    HASH_ALGO_MD5,
                    [
                        0x45, 0x6E, 0xC2, 0x17, 0x7C, 0x10, 0x1E, 0x3C, 0x2E, 0x99, 0x6E, 0xC2,
                        0x9A, 0x3D, 0x50, 0x8E,
                    ],
                ),
            ],
        };

        let mut buf = vec![];

        assert_eq!(packet.write_to::<LittleEndian, _>(&mut buf).unwrap(), 64);

        let (_, packet) = ObsoletedPacket::parse(&buf, Endianness::Little).unwrap();

        assert_eq!(
            packet.flags::<LittleEndian>().unwrap(),
            Flags::INBOUND | Flags::UNICAST
        );
        assert_eq!(
            packet.hash(),
            vec![
                (HASH_ALGO_CRC32, &[0xEC, 0x1D, 0x87, 0x97][..]),
                (
                    HASH_ALGO_MD5,
                    &[
                        0x45, 0x6E, 0xC2, 0x17, 0x7C, 0x10, 0x1E, 0x3C, 0x2E, 0x99, 0x6E, 0xC2,
                        0x9A, 0x3D, 0x50, 0x8E,
                    ][..],
                ),
            ]
        );
        assert_eq!(packet.drops_count.unwrap(), 123);
    }
}
