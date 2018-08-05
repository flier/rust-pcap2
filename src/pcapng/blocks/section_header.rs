use std::io::Write;
use std::mem;

use byteorder::{ByteOrder, WriteBytesExt};
use nom::*;

use errors::{PcapError, Result};
use pcapng::options::{opt, parse_options, Opt, Options, WriteOptions};

pub const BLOCK_TYPE: u32 = 0x0A0D0D0A;

pub const MAGIC: u32 = 0x1A2B3C4D;

pub const DEFAULT_MAJOR_VERSION: u16 = 1;
pub const DEFAULT_MINOR_VERSION: u16 = 0;

/// the description of the hardware used to create this section.
pub const SHB_HARDWARE: u16 = 2;

/// the name of the operating system used to create this section.
pub const SHB_OS: u16 = 3;

/// the name of the application used to create this section.
pub const SHB_USERAPPL: u16 = 4;

/// the description of the hardware used to create this section.
pub fn shb_hardware<'a, T: AsRef<[u8]> + ?Sized>(value: &'a T) -> Opt<'a> {
    opt(SHB_HARDWARE, value)
}

/// the name of the operating system used to create this section.
pub fn shb_os<'a, T: AsRef<[u8]> + ?Sized>(value: &'a T) -> Opt<'a> {
    opt(SHB_OS, value)
}

/// the name of the application used to create this section.
pub fn shb_userappl<'a, T: AsRef<[u8]> + ?Sized>(value: &'a T) -> Opt<'a> {
    opt(SHB_USERAPPL, value)
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
            magic: MAGIC,
            major_version: DEFAULT_MAJOR_VERSION,
            minor_version: DEFAULT_MINOR_VERSION,
            section_length: None,
            options: vec![],
        }
    }
}

impl<'a> SectionHeader<'a> {
    pub fn block_type() -> u32 {
        BLOCK_TYPE
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
        magic: verify!(u32!(endianness), |ty| ty == MAGIC) >>
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

pub trait WriteSectionHeader {
    fn write_section_header<'a, T: ByteOrder>(
        &mut self,
        section_header: &SectionHeader<'a>,
    ) -> Result<usize>;
}

impl<W: Write + ?Sized> WriteSectionHeader for W {
    fn write_section_header<'a, T: ByteOrder>(
        &mut self,
        section_header: &SectionHeader<'a>,
    ) -> Result<usize> {
        self.write_u32::<T>(section_header.magic)?;
        self.write_u16::<T>(section_header.major_version)?;
        self.write_u16::<T>(section_header.minor_version)?;
        self.write_i64::<T>(section_header.section_length.unwrap_or(-1))?;
        self.write_options::<T, _>(&section_header.options)?;

        Ok(section_header.size())
    }
}

#[cfg(test)]
mod tests {
    use byteorder::LittleEndian;

    use super::*;
    use pcapng::{end_of_opt, Block};

    pub const LE_SECTION_HEADER: &[u8] = b"\n\r\r\n\xc0\0\0\0\
\x4d\x3c\x2b\x1a\x01\0\0\0\xff\xff\xff\xff\xff\xff\xff\xff\
\x02\0\x35\0Intel(R) Core(TM) i5-4690 CPU @ 3.50GHz (with SSE4.2)\0\0\0\
\x03\0\x2c\0Mac OS X 10.13, build 17A405 (Darwin 17.0.0)\
\x04\0\x2e\0Dumpcap (Wireshark) 2.6.1 (v2.6.1-0-g860a78b3)\0\0\
\0\0\0\0\
\xc0\0\0\0";

    lazy_static! {
        static ref SECTION_HEADER: SectionHeader<'static> = SectionHeader {
            magic: MAGIC,
            major_version: DEFAULT_MAJOR_VERSION,
            minor_version: DEFAULT_MINOR_VERSION,
            section_length: None,
            options: vec![
                shb_hardware("Intel(R) Core(TM) i5-4690 CPU @ 3.50GHz (with SSE4.2)"),
                shb_os("Mac OS X 10.13, build 17A405 (Darwin 17.0.0)"),
                shb_userappl("Dumpcap (Wireshark) 2.6.1 (v2.6.1-0-g860a78b3)"),
                end_of_opt(),
            ],
        };
    }

    #[test]
    fn test_parse() {
        let (remaining, block) = Block::parse(LE_SECTION_HEADER, Endianness::Little).unwrap();

        assert_eq!(remaining, b"");
        assert_eq!(block.ty, BLOCK_TYPE);
        assert_eq!(block.len, 192);

        let section_header = block.as_section_header(Endianness::Little).unwrap();

        assert_eq!(section_header, *SECTION_HEADER);
    }

    #[test]
    fn test_write() {
        let mut buf = vec![];

        let wrote = buf
            .write_section_header::<LittleEndian>(&SECTION_HEADER.clone())
            .unwrap();

        assert_eq!(wrote, SECTION_HEADER.size());
        assert_eq!(
            buf.as_slice(),
            &LE_SECTION_HEADER[8..LE_SECTION_HEADER.len() - 4]
        );
    }
}