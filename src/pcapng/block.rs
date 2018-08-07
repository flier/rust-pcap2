use std::borrow::Cow;
use std::io::Write;
use std::mem;

use byteorder::{ByteOrder, WriteBytesExt};
use nom::*;

use errors::{PcapError, Result};

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
#[derive(Clone, Debug)]
pub struct Block<'a> {
    /// unique value that identifies the block.
    pub ty: u32,
    /// total size of this block, in octets.
    pub len: u32,
    /// content of the block.
    pub body: Cow<'a, [u8]>,
    /// total size of this block, in octets.
    pub _len: u32,
}

impl<'a> Block<'a> {
    pub fn new<T: AsRef<[u8]>>(ty: u32, body: &'a T) -> Block<'a> {
        let body = body.as_ref();

        Block {
            ty,
            len: body.len() as u32,
            body: body.into(),
            _len: body.len() as u32,
        }
    }

    pub fn size(&self) -> usize {
        mem::size_of::<u32>() * 3 + self.body.len()
    }

    pub fn parse(buf: &'a [u8], endianness: Endianness) -> Result<(&[u8], Self)> {
        parse_block(buf, endianness).map_err(|err| PcapError::from(err).into())
    }
}

named_args!(parse_block(endianness: Endianness)<Block>,
    dbg_dmp!(do_parse!(
        ty: u32!(endianness) >>
        len: u32!(endianness) >>
        body: map!(take!(len as usize - mem::size_of::<u32>() * 3), Cow::from) >>
        _len: verify!(u32!(endianness), |n| n == len) >>
        (
            Block { ty, len, body, _len }
        )
    ))
);

pub trait WriteBlock {
    fn write_block<'a, T: ByteOrder>(&mut self, block: Block<'a>) -> Result<usize>;
}

impl<W: Write + ?Sized> WriteBlock for W {
    fn write_block<'a, T: ByteOrder>(&mut self, block: Block<'a>) -> Result<usize> {
        self.write_u32::<T>(block.ty)?;
        self.write_u32::<T>(block.len)?;
        self.write_all(&block.body)?;
        self.write_u32::<T>(block._len)?;

        Ok(block.size())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_layout() {
        assert_eq!(Block::new(0, b"").size(), 12);
        assert_eq!(Block::new(0, b"test").size(), 16);
    }
}
