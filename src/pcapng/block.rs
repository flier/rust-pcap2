use std::borrow::Cow;
use std::io::Write;
use std::mem;

use byteorder::{ByteOrder, WriteBytesExt};
use nom::*;

use errors::{PcapError, Result};
use pcapng::options::pad_to;
use traits::WriteTo;

pub const MIN_BLOCK_SIZE: u32 = (mem::size_of::<u32>() * 3) as u32;
pub const MAX_BLOCK_SIZE: u32 = 16 * 1024 * 1024;

/// Public representation of a parsed block
///
///
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                          Block Type                           |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                      Block Total Length                       |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  /                          Block Body                           /
///  /          /* variable length, aligned to 32 bits */            /
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                      Block Total Length                       |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Clone, Debug, PartialEq)]
pub struct Block<'a> {
    /// unique value that identifies the block.
    pub ty: u32,
    /// content of the block.
    pub body: Cow<'a, [u8]>,
}

impl<'a> Block<'a> {
    pub fn new<T: AsRef<[u8]>>(ty: u32, body: &'a T) -> Block<'a> {
        Block {
            ty,
            body: body.as_ref().into(),
        }
    }

    pub fn size(&self) -> usize {
        mem::size_of::<u32>() * 3 + pad_to::<u32>(self.body.len())
    }

    pub fn parse(buf: &'a [u8], endianness: Endianness) -> Result<(&[u8], Self)> {
        parse_block(buf, endianness).map_err(|err| PcapError::from(err).into())
    }
}

named_args!(parse_block(endianness: Endianness)<Block>,
    dbg_dmp!(do_parse!(
        ty: u32!(endianness) >>
        block_len: verify!(u32!(endianness), |n| MIN_BLOCK_SIZE <= n && n <= MAX_BLOCK_SIZE) >>
        body: map!(take!(block_len as usize - mem::size_of::<u32>() * 3), Cow::from) >>
        _check_len: verify!(u32!(endianness), |n| n == block_len) >>
        (
            Block { ty, body }
        )
    ))
);

impl<'a> WriteTo for Block<'a> {
    fn write_to<T: ByteOrder, W: Write>(&self, w: &mut W) -> Result<usize> {
        w.write_u32::<T>(self.ty)?;

        let body_len = pad_to::<u32>(self.body.len());
        let block_len = MIN_BLOCK_SIZE as usize + body_len;

        w.write_u32::<T>(block_len as u32)?;
        w.write_all(&self.body)?;

        let padded_len = body_len - self.body.len();
        if padded_len > 0 {
            w.write_all(&vec![0; padded_len])?;
        }

        w.write_u32::<T>(block_len as u32)?;

        Ok(self.size())
    }
}

#[cfg(test)]
mod tests {
    use byteorder::LittleEndian;
    use nom;

    use super::*;

    #[test]
    pub fn test_layout() {
        assert_eq!(Block::new(0, b"").size(), 12);
        assert_eq!(Block::new(0, b"test").size(), 16);
    }

    #[test]
    pub fn test_parse() {
        assert_eq!(
            parse_block(
                b"\x01\x00\x00\x00\x0c\x00\x00\x00\x0c\x00\x00\x00",
                Endianness::Little
            ).unwrap(),
            (&[][..], Block::new(1, b""))
        );
    }

    #[test]
    pub fn test_write() {
        let mut buf = vec![];

        assert_eq!(
            Block::new(1, b"foo")
                .write_to::<LittleEndian, _>(&mut buf)
                .unwrap(),
            16
        );
        assert_eq!(
            buf.as_slice(),
            b"\x01\x00\x00\x00\x10\x00\x00\x00foo\x00\x10\x00\x00\x00"
        );
    }

    #[test]
    pub fn test_corrupted() {
        assert_eq!(
            parse_block(b"", Endianness::Little).unwrap_err(),
            nom::Err::Incomplete(nom::Needed::Size(4))
        );
        assert_eq!(
            parse_block(b"\x01\x00\x00\x00\x0A\x00\x00\x00", Endianness::Little).unwrap_err(),
            nom::Err::Error(nom::Context::Code(
                &b"\x0A\x00\x00\x00"[..],
                nom::ErrorKind::Verify
            ))
        );
        assert_eq!(
            parse_block(b"\x01\x00\x00\x00\x00\x00\x00\x02", Endianness::Little).unwrap_err(),
            nom::Err::Error(nom::Context::Code(
                &b"\x00\x00\x00\x02"[..],
                nom::ErrorKind::Verify
            ))
        );
        assert_eq!(
            parse_block(
                b"\x01\x00\x00\x00\x0c\x00\x00\x00\x0a\x00\x00\x00",
                Endianness::Little
            ).unwrap_err(),
            nom::Err::Error(nom::Context::Code(
                &b"\x0a\x00\x00\x00"[..],
                nom::ErrorKind::Verify
            ))
        );
    }
}
