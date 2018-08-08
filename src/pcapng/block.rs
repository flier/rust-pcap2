use std::borrow::Cow;
use std::io::{Read, Seek, SeekFrom, Write};
use std::mem;

use byteorder::{ByteOrder, NativeEndian, ReadBytesExt, WriteBytesExt};
use nom::*;
use num_traits::FromPrimitive;

use errors::{PcapError, Result};
use pcapng::blocks::{
    section_header::{SectionHeader, BYTE_ORDER_MAGIC_BE, BYTE_ORDER_MAGIC_LE},
    BlockType,
};
use pcapng::options::pad_to;
use traits::WriteTo;

pub const BLOCK_HEADER_SIZE: usize = mem::size_of::<u32>() * 2;
pub const BLOCK_TRAILER_SIZE: usize = mem::size_of::<u32>();
pub const BLOCK_OVERHEAD_SIZE: usize = BLOCK_HEADER_SIZE + BLOCK_TRAILER_SIZE;
pub const MIN_BLOCK_SIZE: u32 = BLOCK_OVERHEAD_SIZE as u32;
pub const MAX_BLOCK_SIZE: u32 = 16 * 1024 * 1024;

/// Public representation of a parsed block
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

    pub fn min_size() -> usize {
        MIN_BLOCK_SIZE as usize
    }

    pub fn max_size() -> usize {
        MAX_BLOCK_SIZE as usize
    }

    pub fn block_type(&self) -> Option<BlockType> {
        BlockType::from_u32(self.ty)
    }

    pub fn size(&self) -> usize {
        BLOCK_HEADER_SIZE + pad_to::<u32>(self.body.len()) + BLOCK_TRAILER_SIZE
    }

    pub fn parse(buf: &'a [u8], endianness: Endianness) -> Result<(&[u8], Self)> {
        parse_block(buf, endianness).map_err(|err| PcapError::from(err).into())
    }
}

pub trait ReadFileHeader {
    fn read_file_header(&mut self) -> Result<Endianness>;
}

impl<R: Read + Seek> ReadFileHeader for R {
    fn read_file_header(&mut self) -> Result<Endianness> {
        let mut buf = [0; 12];

        self.read_exact(&mut buf)?;
        self.seek(SeekFrom::Current(-(buf.len() as i64)))?;

        let block_type = NativeEndian::read_u32(&buf[..4]);

        if block_type != SectionHeader::block_type() as u32 {
            bail!("file MUST begin with a Section Header Block.")
        }

        let byte_order_magic = &buf[8..12];

        if byte_order_magic == BYTE_ORDER_MAGIC_LE {
            Ok(Endianness::Little)
        } else if byte_order_magic == BYTE_ORDER_MAGIC_BE {
            Ok(Endianness::Big)
        } else {
            bail!("unkwnon byte order magic word: {:?}", byte_order_magic)
        }
    }
}

pub trait ReadBlock {
    fn read_block<'a, T: ByteOrder>(&mut self) -> Result<Block<'a>>;
}

impl<R: Read> ReadBlock for R {
    fn read_block<'a, T: ByteOrder>(&mut self) -> Result<Block<'a>> {
        let block_type = self.read_u32::<T>()?;
        let block_len = self.read_u32::<T>()? as usize;

        if block_len < Block::min_size() {
            bail!("block too small, {}", block_len);
        }
        if block_len > Block::max_size() {
            bail!("block too large, {}", block_len);
        }

        let mut buf = vec![0; pad_to::<u32>(block_len - BLOCK_OVERHEAD_SIZE)];

        self.read_exact(&mut buf)?;

        let check_len = self.read_u32::<T>()? as usize;

        if check_len != block_len {
            debug!("block body:\n{}", hexdump!(buf));

            bail!(
                "block check length mismatch, block_len = {}, check_len {}",
                block_len,
                check_len
            );
        }

        Ok(Block {
            ty: block_type,
            body: buf.into(),
        })
    }
}

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
named_args!(parse_block(endianness: Endianness)<Block>,
    dbg_dmp!(do_parse!(
        ty: u32!(endianness) >>
        block_len: verify!(u32!(endianness), |n| MIN_BLOCK_SIZE <= n && n <= MAX_BLOCK_SIZE) >>
        body: map!(take!(block_len as usize - BLOCK_OVERHEAD_SIZE), Cow::from) >>
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
