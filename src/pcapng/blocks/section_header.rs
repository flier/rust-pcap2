use std::io::{Read, Seek, SeekFrom, Write};
use std::mem;
use std::str;

use byteorder::{ByteOrder, NativeEndian, WriteBytesExt};
use nom::*;

use errors::{PcapError, Result};
use pcapng::options::{opt, parse_options, Opt, Options};
use pcapng::{Block, BlockType};
use traits::WriteTo;

pub const BLOCK_TYPE: u32 = 0x0A0D_0D0A;

pub const BYTE_ORDER_MAGIC: u32 = 0x1A2B_3C4D;
pub const BYTE_ORDER_MAGIC_LE: &[u8] = b"\x4D\x3C\x2B\x1A";
pub const BYTE_ORDER_MAGIC_BE: &[u8] = b"\x1A\x2B\x3C\x4D";

pub const DEFAULT_MAJOR_VERSION: u16 = 1;
pub const DEFAULT_MINOR_VERSION: u16 = 0;

/// the description of the hardware used to create this section.
pub const SHB_HARDWARE: u16 = 2;

/// the name of the operating system used to create this section.
pub const SHB_OS: u16 = 3;

/// the name of the application used to create this section.
pub const SHB_USERAPPL: u16 = 4;

/// the description of the hardware used to create this section.
pub fn shb_hardware<T: AsRef<str> + ?Sized>(value: &T) -> Opt {
    opt(SHB_HARDWARE, value.as_ref())
}

/// the name of the operating system used to create this section.
pub fn shb_os<T: AsRef<str> + ?Sized>(value: &T) -> Opt {
    opt(SHB_OS, value.as_ref())
}

/// the name of the application used to create this section.
pub fn shb_userappl<T: AsRef<str> + ?Sized>(value: &T) -> Opt {
    opt(SHB_USERAPPL, value.as_ref())
}

/// The `SectionHeader` identifies the beginning of a section of the capture capture file.
#[derive(Clone, Debug, PartialEq)]
pub struct SectionHeader<'a> {
    /// magic number, whose value is the hexadecimal number 0x1A2B3C4D.
    pub magic: u32,
    /// number of the current mayor version of the format.
    pub major_version: u16,
    /// number of the current minor version of the format.
    pub minor_version: u16,
    /// specifying the length in octets of the following section, excluding the Section Header Block itself.
    pub section_length: Option<i64>,
    /// a list of options
    pub options: Options<'a>,
}

impl<'a> Default for SectionHeader<'a> {
    fn default() -> Self {
        SectionHeader {
            magic: BYTE_ORDER_MAGIC,
            major_version: DEFAULT_MAJOR_VERSION,
            minor_version: DEFAULT_MINOR_VERSION,
            section_length: None,
            options: vec![],
        }
    }
}

impl<'a> SectionHeader<'a> {
    pub fn block_type() -> BlockType {
        BlockType::SectionHeader
    }

    pub fn size(&self) -> usize {
        self.options.iter().fold(
            mem::size_of::<u32>() + mem::size_of::<u16>() * 2 + mem::size_of::<i64>(),
            |size, opt| size + opt.size(),
        )
    }

    pub fn parse(buf: &'a [u8], endianness: Endianness) -> Result<(&'a [u8], Self)> {
        parse_section_header(buf, endianness).map_err(|err| PcapError::from(err).into())
    }

    pub fn hardware(&self) -> Option<&str> {
        self.options
            .iter()
            .find(|opt| opt.code == SHB_HARDWARE)
            .and_then(|opt| opt.as_str())
    }

    pub fn os(&self) -> Option<&str> {
        self.options
            .iter()
            .find(|opt| opt.code == SHB_OS)
            .and_then(|opt| opt.as_str())
    }

    pub fn userappl(&self) -> Option<&str> {
        self.options
            .iter()
            .find(|opt| opt.code == SHB_USERAPPL)
            .and_then(|opt| opt.as_str())
    }

    pub fn peek_endianness<R: Read + Seek>(r: &mut R) -> Result<Endianness> {
        let mut buf = [0; 12];

        r.read_exact(&mut buf)?;
        r.seek(SeekFrom::Current(-(buf.len() as i64)))?;

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

///    0                   1                   2                   3
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///    +---------------------------------------------------------------+
///  0 |                   Block Type = 0x0A0D0D0A                     |
///    +---------------------------------------------------------------+
///  4 |                      Block Total Length                       |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  8 |                      Byte-Order Magic                         |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// 12 |          Major Version        |         Minor Version         |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// 16 |                                                               |
///    |                          Section Length                       |
///    |                                                               |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// 24 /                                                               /
///    /                      Options (variable)                       /
///    /                                                               /
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    |                      Block Total Length                       |
///    +---------------------------------------------------------------+
named_args!(parse_section_header(endianness: Endianness)<SectionHeader>,
    do_parse!(
        magic: verify!(u32!(endianness), |ty| ty == BYTE_ORDER_MAGIC) >>
        major_version: u16!(endianness) >>
        minor_version: u16!(endianness) >>
        section_length: i64!(endianness) >>
        options: apply!(parse_options, endianness) >>
        (
            SectionHeader {
                magic,
                major_version,
                minor_version,
                section_length: if section_length < 0 { None } else { Some(section_length) },
                options,
            }
        )
    )
);

impl<'a> WriteTo for SectionHeader<'a> {
    fn write_to<T: ByteOrder, W: Write>(&self, w: &mut W) -> Result<usize> {
        w.write_u32::<T>(self.magic)?;
        w.write_u16::<T>(self.major_version)?;
        w.write_u16::<T>(self.minor_version)?;
        w.write_i64::<T>(self.section_length.unwrap_or(-1))?;
        self.options.write_to::<T, _>(w)?;

        Ok(self.size())
    }
}

impl<'a> Block<'a> {
    pub fn is_section_header(&self) -> bool {
        self.ty == BLOCK_TYPE
    }

    pub fn as_section_header(&'a self, endianness: Endianness) -> Option<SectionHeader<'a>> {
        if self.is_section_header() {
            SectionHeader::parse(&self.body, endianness)
                .map(|(_, section_header)| section_header)
                .map_err(|err| {
                    warn!("fail to parse section header: {:?}", err);

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
    use pcapng::Block;

    pub const LE_SECTION_HEADER: &[u8] = b"\n\r\r\n\xc0\0\0\0\
\x4d\x3c\x2b\x1a\x01\0\0\0\xff\xff\xff\xff\xff\xff\xff\xff\
\x02\0\x35\0Intel(R) Core(TM) i5-4690 CPU @ 3.50GHz (with SSE4.2)\0\0\0\
\x03\0\x2c\0Mac OS X 10.13, build 17A405 (Darwin 17.0.0)\
\x04\0\x2e\0Dumpcap (Wireshark) 2.6.1 (v2.6.1-0-g860a78b3)\0\0\
\0\0\0\0\
\xc0\0\0\0";

    lazy_static! {
        static ref SECTION_HEADER: SectionHeader<'static> = SectionHeader {
            magic: BYTE_ORDER_MAGIC,
            major_version: DEFAULT_MAJOR_VERSION,
            minor_version: DEFAULT_MINOR_VERSION,
            section_length: None,
            options: vec![
                shb_hardware("Intel(R) Core(TM) i5-4690 CPU @ 3.50GHz (with SSE4.2)"),
                shb_os("Mac OS X 10.13, build 17A405 (Darwin 17.0.0)"),
                shb_userappl("Dumpcap (Wireshark) 2.6.1 (v2.6.1-0-g860a78b3)"),
            ],
        };
    }

    #[test]
    fn test_parse() {
        let (remaining, block) = Block::parse(LE_SECTION_HEADER, Endianness::Little).unwrap();

        assert_eq!(remaining, b"");
        assert_eq!(block.ty, BLOCK_TYPE);
        assert_eq!(block.size(), LE_SECTION_HEADER.len());

        let section_header = block.as_section_header(Endianness::Little).unwrap();

        assert_eq!(section_header, *SECTION_HEADER);
    }

    #[test]
    fn test_write() {
        let mut buf = vec![];

        let wrote = SECTION_HEADER
            .write_to::<LittleEndian, _>(&mut buf)
            .unwrap();

        assert_eq!(wrote, SECTION_HEADER.size());
        assert_eq!(
            buf.as_slice(),
            &LE_SECTION_HEADER[8..LE_SECTION_HEADER.len() - 4]
        );
    }
}
