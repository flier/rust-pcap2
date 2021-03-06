use std::io::Write;
use std::mem;

use byteorder::{ByteOrder, NativeEndian, WriteBytesExt};
use nom::*;
use num_traits::FromPrimitive;

use errors::{PcapError, Result};
use linktype::LinkType;
use traits::AsEndianness;

#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, FromPrimitive)]
pub enum Magic {
    /// same byte order as in memory, timestamps with microsecond resolution
    Normal = 0xa1b2_c3d4,
    /// same byte order as in memory, timestamps with nanosecond resolution
    NanoSecondResolution = 0xa1b2_3c4d,
    /// different byte order than in memory, timestamps with microsecond resolution
    ByteSwap = 0xd4c3_b2a1,
    /// different byte order than in memory, timestamps with nanosecond resolution
    NanoSecondResolutionByteSwap = 0x4d3c_b2a1,
}

impl Magic {
    pub fn endianness(self) -> Endianness {
        match self {
            Magic::Normal | Magic::NanoSecondResolution => Endianness::Little,
            Magic::ByteSwap | Magic::NanoSecondResolutionByteSwap => Endianness::Big,
        }
    }

    pub fn is_nanosecond_resolution(self) -> bool {
        match self {
            Magic::Normal | Magic::ByteSwap => false,
            Magic::NanoSecondResolution | Magic::NanoSecondResolutionByteSwap => true,
        }
    }
}

/// only supported major version
pub const DEFAULT_VERSION_MAJOR: u16 = 2;
/// only supported minor version
pub const DEFAULT_VERSION_MINOR: u16 = 4;

pub const DEFAULT_SNAPLEN: u32 = u16::max_value() as u32;

#[derive(Clone, Debug)]
pub struct Header {
    /// magic number
    pub magic_number: u32,
    /// major version number
    pub version_major: u16,
    /// minor version number
    pub version_minor: u16,
    /// GMT to local correction
    pub thiszone: i32,
    /// accuracy of timestamps
    pub sigfigs: u32,
    /// max length of captured packets, in octets
    pub snaplen: u32,
    /// data link type
    pub network: u32,
}

impl Header {
    pub fn new<T: AsEndianness>() -> Self {
        Header {
            magic_number: if NativeEndian::endianness() == T::endianness() {
                Magic::NanoSecondResolution
            } else {
                Magic::NanoSecondResolutionByteSwap
            } as u32,
            version_major: DEFAULT_VERSION_MAJOR,
            version_minor: DEFAULT_VERSION_MINOR,
            thiszone: 0,
            sigfigs: 0,
            snaplen: DEFAULT_SNAPLEN,
            network: LinkType::NULL as u32,
        }
    }

    pub fn parse(buf: &[u8]) -> Result<(&[u8], Self)> {
        parse_header(buf).map_err(|err| PcapError::from(err).into())
    }

    pub fn size() -> usize {
        mem::size_of::<Self>()
    }

    pub fn magic(&self) -> Magic {
        Magic::from_u32(self.magic_number).unwrap()
    }

    pub fn link_type(&self) -> LinkType {
        LinkType::from_u32(self.network).unwrap_or_default()
    }
}

#[cfg_attr(rustfmt, rustfmt_skip)]
named!(parse_header<Header>,
    do_parse!(
        magic_number: map!(take!(4), NativeEndian::read_u32) >>
        endianness: switch!(expr_opt!(Magic::from_u32(magic_number)),
            Magic::Normal                       => value!(Endianness::Little) |
            Magic::NanoSecondResolution         => value!(Endianness::Little) |
            Magic::ByteSwap                     => value!(Endianness::Big) |
            Magic::NanoSecondResolutionByteSwap => value!(Endianness::Big)
        ) >>
        version_major: u16!(endianness) >>
        version_minor: u16!(endianness) >>
        thiszone: i32!(endianness) >>
        sigfigs: u32!(endianness) >>
        snaplen: u32!(endianness) >>
        network: u32!(endianness) >>
        (
            Header {
                magic_number,
                version_major,
                version_minor,
                thiszone,
                sigfigs,
                snaplen,
                network,
            }
        )
    )
);

pub trait WriteHeaderExt {
    fn write_header<T: ByteOrder>(&mut self, header: &Header) -> Result<usize>;
}

impl<W: Write + ?Sized> WriteHeaderExt for W {
    fn write_header<T: ByteOrder>(&mut self, header: &Header) -> Result<usize> {
        self.write_u32::<NativeEndian>(header.magic_number)?;
        self.write_u16::<T>(header.version_major)?;
        self.write_u16::<T>(header.version_minor)?;
        self.write_i32::<T>(header.thiszone)?;
        self.write_u32::<T>(header.sigfigs)?;
        self.write_u32::<T>(header.snaplen)?;
        self.write_u32::<T>(header.network)?;

        Ok(Header::size())
    }
}

#[cfg(test)]
mod tests {
    use byteorder::{BigEndian, LittleEndian};

    use pcap::tests::PACKETS;

    use super::*;

    #[test]
    pub fn test_layout() {
        assert_eq!(Header::size(), 24)
    }

    #[test]
    pub fn test_parse() {
        for (buf, magic) in PACKETS.iter() {
            let (remaining, header) = Header::parse(buf).unwrap();

            assert_eq!(buf.len() - remaining.len(), Header::size());

            assert_eq!(header.magic(), *magic);
            assert_eq!(header.version_major, DEFAULT_VERSION_MAJOR);
            assert_eq!(header.version_minor, DEFAULT_VERSION_MINOR);
            assert_eq!(header.thiszone, 0);
            assert_eq!(header.sigfigs, 0);
            assert_eq!(header.snaplen, DEFAULT_SNAPLEN);
            assert_eq!(header.network, 101);
            assert_eq!(header.link_type(), LinkType::RAW);
        }
    }

    #[test]
    pub fn test_write() {
        for (buf, magic) in PACKETS.iter() {
            let header = Header {
                magic_number: *magic as u32,
                version_major: DEFAULT_VERSION_MAJOR,
                version_minor: DEFAULT_VERSION_MINOR,
                thiszone: 0,
                sigfigs: 0,
                snaplen: DEFAULT_SNAPLEN,
                network: LinkType::RAW as u32,
            };

            let mut data = vec![];
            let len = match magic.endianness() {
                Endianness::Little => data.write_header::<LittleEndian>(&header),
                Endianness::Big => data.write_header::<BigEndian>(&header),
            }.unwrap();

            assert_eq!(data.as_slice(), &buf[..len]);
        }
    }
}
