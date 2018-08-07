use std::borrow::Cow;
use std::io::Write;
use std::iter::once;
use std::mem;

use byteorder::{ByteOrder, WriteBytesExt};
use nom::*;

use errors::{PcapError, Result};
use pcapng::options::{pad_to, parse_options, Opt, Options, WriteOptions};
use pcapng::Block;

pub const BLOCK_TYPE: u32 = 0x00000006;

pub const EPB_FLAGS: u16 = 2;
pub const EPB_HASH: u16 = 3;
pub const EPB_DROPCOUNT: u16 = 4;

bitflags! {
    pub struct Flags: u32 {
        const INBOUND   = 1;
        const OUTBOUND  = 2;

        const UNICAST       = 1 << 2;
        const MULTICAST     = 2 << 2;
        const BROADCAST     = 3 << 2;
        const PROMISCUOUS   = 4 << 2;

        const FCS_LEN_MASK  = 0xF << 5;

        const CRC_ERROR             = 1 << 24;
        const PACKET_TOO_LONG       = 1 << 25;
        const PACKET_TOO_SHORT      = 1 << 26;
        const WRONG_INTER_FRAME_GAP = 1 << 27;
        const UNALIGNED_FRAME       = 1 << 28;
        const START_FRAME_DELIMITER = 1 << 29;
        const PREAMBLE_ERROR        = 1 << 30;
        const SYMBOL_ERROR          = 1 << 31;
    }
}

/// This option is a 32-bit flags word containing link-layer information.
pub fn epb_flags<'a, T: ByteOrder>(flags: Flags) -> Opt<'a> {
    Opt::u32::<T>(EPB_FLAGS, flags.bits())
}

pub const HASH_ALGO_2S_COMPLEMENT: u8 = 0;
pub const HASH_ALGO_XOR: u8 = 1;
pub const HASH_ALGO_CRC32: u8 = 2;
pub const HASH_ALGO_MD5: u8 = 3;
pub const HASH_ALGO_SHA1: u8 = 4;

/// This option contains a hash of the packet.
pub fn epb_hash<'a, T: AsRef<[u8]>>(algorithm: u8, hash: T) -> Opt<'a> {
    Opt::from_iter(
        EPB_HASH,
        once(algorithm).chain(hash.as_ref().iter().cloned()),
    )
}

/// This option is a 64-bit integer value specifying the number of packets lost
pub fn epb_dropcount<'a, T: ByteOrder>(count: u64) -> Opt<'a> {
    Opt::u64::<T>(EPB_DROPCOUNT, count)
}

/// An Enhanced Packet Block is the standard container for storing the packets coming from the
/// network.
#[derive(Clone, Debug, PartialEq)]
pub struct EnhancedPacket<'a> {
    /// the interface this packet comes from
    pub interface_id: u32,
    /// the number of units of time that have elapsed since 1970-01-01 00:00:00 UTC.
    pub timestamp: u64,
    /// number of octets captured from the packet.
    pub captured_len: u32,
    /// actual length of the packet when it was transmitted on the network.
    pub original_len: u32,
    /// the data coming from the network, including link-layer headers.
    pub data: Cow<'a, [u8]>,
    /// optionally, a list of options
    pub options: Options<'a>,
}

impl<'a> EnhancedPacket<'a> {
    pub fn block_type() -> u32 {
        BLOCK_TYPE
    }

    pub fn size(&self) -> usize {
        self.options.iter().fold(
            mem::size_of::<u32>() * 3 + mem::size_of::<u64>() + pad_to::<u32>(self.data.len()),
            |size, opt| size + opt.size(),
        )
    }

    pub fn parse(buf: &'a [u8], endianness: Endianness) -> Result<(&'a [u8], Self)> {
        parse_enhanced_packet(buf, endianness).map_err(|err| PcapError::from(err).into())
    }

    pub fn flags<T: ByteOrder>(&self) -> Option<Flags> {
        self.options
            .iter()
            .find(|opt| opt.code == EPB_FLAGS && opt.len as usize == mem::size_of::<u32>())
            .map(|opt| Flags::from_bits_truncate(T::read_u32(opt.value())))
    }

    pub fn hash(&self) -> Vec<(u8, &[u8])> {
        self.options
            .iter()
            .filter(|opt| opt.code == EPB_HASH && opt.len > 0)
            .map(|opt| (opt.value()[0], &opt.value()[1..]))
            .collect()
    }

    pub fn dropcount<T: ByteOrder>(&self) -> Option<u64> {
        self.options
            .iter()
            .find(|opt| opt.code == EPB_DROPCOUNT && opt.len as usize == mem::size_of::<u64>())
            .map(|opt| T::read_u64(opt.value()))
    }
}

///    0                   1                   2                   3
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///    +---------------------------------------------------------------+
///  0 |                    Block Type = 0x00000006                    |
///    +---------------------------------------------------------------+
///  4 |                      Block Total Length                       |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  8 |                         Interface ID                          |
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
named_args!(parse_enhanced_packet(endianness: Endianness)<EnhancedPacket>,
    dbg_dmp!(do_parse!(
        interface_id: u32!(endianness) >>
        timestamp_hi: u32!(endianness) >>
        timestamp_lo: u32!(endianness) >>
        captured_len: u32!(endianness) >>
        original_len: u32!(endianness) >>
        data: take!(pad_to::<u32>(captured_len as usize)) >>
        options: apply!(parse_options, endianness) >>
        (
            EnhancedPacket {
                interface_id,
                timestamp: (u64::from(timestamp_hi ) << 32) + u64::from(timestamp_lo),
                captured_len,
                original_len,
                data: Cow::from(&data[..captured_len as usize]),
                options,
            }
        )
    ))
);

pub trait WriteEnhancedPacket {
    fn write_enhanced_packet<'a, T: ByteOrder>(
        &mut self,
        packet: &EnhancedPacket<'a>,
    ) -> Result<usize>;
}

impl<W: Write + ?Sized> WriteEnhancedPacket for W {
    fn write_enhanced_packet<'a, T: ByteOrder>(
        &mut self,
        packet: &EnhancedPacket<'a>,
    ) -> Result<usize> {
        self.write_u32::<T>(packet.interface_id)?;
        self.write_u32::<T>((packet.timestamp >> 32) as u32)?;
        self.write_u32::<T>(packet.timestamp as u32)?;
        self.write_u32::<T>(packet.captured_len)?;
        self.write_u32::<T>(packet.original_len)?;
        self.write(&packet.data)?;
        let padded_len = pad_to::<u32>(packet.data.len()) - packet.data.len();
        if padded_len > 0 {
            self.write(&vec![0; padded_len])?;
        }
        self.write_options::<T, _>(&packet.options)?;

        Ok(packet.size())
    }
}

impl<'a> Block<'a> {
    pub fn as_enhanced_packet(&'a self, endianness: Endianness) -> Option<EnhancedPacket<'a>> {
        if self.ty == EnhancedPacket::block_type() {
            EnhancedPacket::parse(&self.body, endianness)
                .map(|(_, packet)| packet)
                .map_err(|err| {
                    warn!("fail to parse enhanced packet: {:?}", err);

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

    pub const LE_ENHANCED_PACKET: &[u8] = b"\x06\x00\x00\x00\
\x64\x00\x00\x00\
\x00\x00\x00\x00\
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
        static ref ENHANCED_PACKET: EnhancedPacket<'static> = EnhancedPacket {
            interface_id: 0,
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
        let (remaining, block) = Block::parse(LE_ENHANCED_PACKET, Endianness::Little).unwrap();

        assert_eq!(remaining, b"");
        assert_eq!(block.ty, BLOCK_TYPE);
        assert_eq!(block.len as usize, LE_ENHANCED_PACKET.len());

        let enhanced_packet = block.as_enhanced_packet(Endianness::Little).unwrap();

        assert_eq!(enhanced_packet, *ENHANCED_PACKET);
    }

    #[test]
    fn test_write() {
        let mut buf = vec![];

        let wrote = buf.write_enhanced_packet::<LittleEndian>(&ENHANCED_PACKET.clone())
            .unwrap();

        assert_eq!(wrote, ENHANCED_PACKET.size());
        assert_eq!(
            buf.as_slice(),
            &LE_ENHANCED_PACKET[8..LE_ENHANCED_PACKET.len() - 4]
        );
    }

    #[test]
    fn test_options() {
        let packet = EnhancedPacket {
            interface_id: 0,
            timestamp: 0,
            captured_len: 0,
            original_len: 0,
            data: Cow::from(&[][..]),
            options: vec![
                epb_flags::<LittleEndian>(Flags::INBOUND | Flags::UNICAST),
                epb_hash(HASH_ALGO_CRC32, [0xEC, 0x1D, 0x87, 0x97]),
                epb_hash(
                    HASH_ALGO_MD5,
                    [
                        0x45, 0x6E, 0xC2, 0x17, 0x7C, 0x10, 0x1E, 0x3C, 0x2E, 0x99, 0x6E, 0xC2,
                        0x9A, 0x3D, 0x50, 0x8E,
                    ],
                ),
                epb_dropcount::<LittleEndian>(123),
            ],
        };

        let mut buf = vec![];

        buf.write_enhanced_packet::<LittleEndian>(&packet).unwrap();

        let (_, packet) = EnhancedPacket::parse(&buf, Endianness::Little).unwrap();

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
        assert_eq!(packet.dropcount::<LittleEndian>().unwrap(), 123);
    }
}
