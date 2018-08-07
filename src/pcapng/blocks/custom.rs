use std::borrow::Cow;
use std::io::Write;
use std::mem;

use byteorder::{ByteOrder, WriteBytesExt};
use nom::*;

use errors::{PcapError, Result};
use pcapng::block::Block;
use pcapng::options::{pad_to, Options};
use traits::WriteTo;

pub const BLOCK_TYPE: u32 = 0x0000_0BAD;
pub const PRIVATE_BLOCK_TYPE: u32 = 0x4000_0BAD;

/// A Custom Block (CB) is the container for storing custom data that is not part of another block
#[derive(Clone, Debug, PartialEq)]
pub struct CustomBlock<'a> {
    /// An IANA-assigned Private Enterprise Number identifying the organization which defined the Custom Block.
    pub private_enterprise_number: u32,
    /// the custom data
    pub data: Cow<'a, [u8]>,
    /// optionally, a list of options
    pub options: Options<'a>,
}

impl<'a> CustomBlock<'a> {
    pub fn block_type() -> u32 {
        BLOCK_TYPE
    }

    pub fn size(&self) -> usize {
        self.options
            .iter()
            .fold(mem::size_of::<u32>() + self.data.len(), |size, opt| {
                size + opt.size()
            })
    }

    pub fn parse(buf: &'a [u8], endianness: Endianness) -> Result<(&'a [u8], Self)> {
        parse_custom_block(buf, endianness).map_err(|err| PcapError::from(err).into())
    }
}

///    0                   1                   2                   3
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///    +---------------------------------------------------------------+
///  0 |             Block Type = 0x00000BAD or 0x40000BAD             |
///    +---------------------------------------------------------------+
///  4 |                      Block Total Length                       |
///    +---------------------------------------------------------------+
///  8 |                Private Enterprise Number (PEN)                |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// 12 /                                                               /
///    /                          Custom Data                          /
///    /              variable length, padded to 32 bits               /
///    /                                                               /
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    /                                                               /
///    /                      Options (variable)                       /
///    /                                                               /
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    |                      Block Total Length                       |
///    +---------------------------------------------------------------+
named_args!(parse_custom_block(endianness: Endianness)<CustomBlock>,
    dbg_dmp!(do_parse!(
        private_enterprise_number: u32!(endianness) >>
        data: rest >>
        (
            CustomBlock {
                private_enterprise_number,
                data: data.into(),
                options: Default::default(),
            }
        )
    ))
);

impl<'a> WriteTo for CustomBlock<'a> {
    fn write_to<T: ByteOrder, W: Write>(&self, w: &mut W) -> Result<usize> {
        w.write_u32::<T>(self.private_enterprise_number)?;
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
    pub fn as_custom_block(&'a self, endianness: Endianness) -> Option<CustomBlock<'a>> {
        if self.ty == CustomBlock::block_type() {
            CustomBlock::parse(&self.body, endianness)
                .map(|(_, packet)| packet)
                .map_err(|err| {
                    warn!("fail to parse custom block: {:?}", err);

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

    pub const LE_CUSTOM_BLOCK: &[u8] = b"\xAD\x0B\x00\x00\
\x1C\x00\x00\x00\
\x7B\x00\x00\x00\
hello world\x00\
\x1C\x00\x00\x00";

    lazy_static! {
        static ref CUSTOM_BLOCK: CustomBlock<'static> = CustomBlock {
            private_enterprise_number: 123,
            data: Cow::from(&b"hello world\x00"[..]),
            options: vec![],
        };
    }

    #[test]
    fn test_parse() {
        let (remaining, block) = Block::parse(LE_CUSTOM_BLOCK, Endianness::Little).unwrap();

        assert_eq!(remaining, b"");
        assert_eq!(block.ty, BLOCK_TYPE);
        assert_eq!(block.size(), LE_CUSTOM_BLOCK.len());

        let custom = block.as_custom_block(Endianness::Little).unwrap();

        assert_eq!(custom, *CUSTOM_BLOCK);
    }

    #[test]
    fn test_write() {
        let mut buf = vec![];

        let wrote = CUSTOM_BLOCK.write_to::<LittleEndian, _>(&mut buf).unwrap();

        assert_eq!(wrote, CUSTOM_BLOCK.size());
        assert_eq!(
            buf.as_slice(),
            &LE_CUSTOM_BLOCK[8..LE_CUSTOM_BLOCK.len() - 4]
        );
    }
}
