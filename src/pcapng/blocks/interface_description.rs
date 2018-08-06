use std::io::Write;
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr};

use byteorder::{ByteOrder, WriteBytesExt};
use nom::*;

use errors::{PcapError, Result};
use pcapng::options::{opt, parse_options, Opt, Options, WriteOptions};
use pcapng::Block;
use LinkType;

pub const BLOCK_TYPE: u32 = 0x00000001;

pub const IF_NAME: u16 = 2;
pub const IF_DESCRIPTION: u16 = 3;
pub const IF_IPV4ADDR: u16 = 4;
pub const IF_IPV6ADDR: u16 = 5;
pub const IF_MACADDR: u16 = 6;
pub const IF_EUIADDR: u16 = 7;
pub const IF_SPEED: u16 = 8;
pub const IF_TSRESOL: u16 = 9;
pub const IF_TZONE: u16 = 10;
pub const IF_FILTER: u16 = 11;
pub const IF_OS: u16 = 12;
pub const IF_FCSLEN: u16 = 13;
pub const IF_TSOFFSET: u16 = 14;

/// This option is a UTF-8 string containing the name of the device used to capture data.
pub fn if_name<'a, T: AsRef<str> + ?Sized>(value: &'a T) -> Opt<'a> {
    opt(IF_NAME, value.as_ref())
}

/// This option is a UTF-8 string containing the description of the device used to capture data.
pub fn if_description<'a, T: AsRef<str> + ?Sized>(value: &'a T) -> Opt<'a> {
    opt(IF_DESCRIPTION, value.as_ref())
}

/// This option s an IPv4 network address and corresponding netmask for the interface.
pub fn if_ipv4addr<'a, T: Into<Ipv4Addr>>(addr: T, mask: T) -> Opt<'a> {
    Opt::from_iter(
        IF_IPV4ADDR,
        addr.into()
            .octets()
            .into_iter()
            .chain(mask.into().octets().into_iter())
            .cloned(),
    )
}

/// This option is an IPv6 network address and corresponding prefix length for the interface.
pub fn if_ipv6addr<'a, T: Into<Ipv6Addr>>(addr: T, prefix: u8) -> Opt<'a> {
    Opt::from_iter(
        IF_IPV6ADDR,
        addr.into()
            .octets()
            .into_iter()
            .chain([prefix].into_iter())
            .cloned(),
    )
}

pub type MacAddr = [u8; 6];

/// This option is the Interface Hardware MAC address (48 bits), if available.
pub fn if_macaddr<'a>(addr: MacAddr) -> Opt<'a> {
    Opt::from_iter(IF_MACADDR, addr.into_iter().cloned())
}

pub type EuiAddr = [u8; 8];

/// This option is the Interface Hardware EUI address (64 bits), if available.
pub fn if_euiaddr<'a>(addr: EuiAddr) -> Opt<'a> {
    Opt::from_iter(IF_EUIADDR, addr.into_iter().cloned())
}

/// This option is a 64-bit number for the Interface speed (in bits per second).
pub fn if_speed<'a, T: ByteOrder>(value: u64) -> Opt<'a> {
    Opt::u64::<T>(IF_SPEED, value)
}

/// This option identifies the resolution of timestamps.
pub fn if_tsresol<'a>(resolution: i8) -> Opt<'a> {
    Opt::new(
        IF_TSRESOL,
        vec![if resolution < 0 {
            (resolution.abs() as u8) | 0x80
        } else {
            resolution as u8
        }],
    )
}

/// This option identifies the time zone for GMT support.
pub fn if_tzone<'a, T: ByteOrder>(tzone: u32) -> Opt<'a> {
    Opt::u32::<T>(IF_TZONE, tzone)
}

/// This option identifies the filter (e.g. "capture only TCP traffic") used to capture traffic.
pub fn if_filter<'a, T: AsRef<str> + ?Sized>(value: &'a T) -> Opt<'a> {
    opt(IF_FILTER, value.as_ref())
}

/// This  option is a UTF-8 string containing the name of the operating system of the machine
/// in which this interface is installed.
pub fn if_os<'a, T: AsRef<str> + ?Sized>(value: &'a T) -> Opt<'a> {
    opt(IF_OS, value.as_ref())
}

/// This option is an 8-bit unsigned integer value that specifies
/// the length of the Frame Check Sequence (in bits) for this interface.
pub fn if_fcslen<'a>(bits: u8) -> Opt<'a> {
    Opt::new(IF_FCSLEN, vec![bits])
}

/// This option is a 64-bit integer value that specifies an offset (in seconds)
/// that must be added to the timestamp of each packet to obtain the absolute timestamp of a packet.
pub fn if_tsoffset<'a, T: ByteOrder>(value: u64) -> Opt<'a> {
    Opt::u64::<T>(IF_TSOFFSET, value)
}

/// An Interface Description Block (IDB) is the container for information describing an interface
/// on which packet data is captured.
#[derive(Clone, Debug, PartialEq)]
pub struct InterfaceDescription<'a> {
    /// a value that defines the link layer type of this interface.
    pub link_type: u16,
    /// not used
    pub reserved: u16,
    /// maximum number of octets captured from each packet.
    pub snap_len: u32,
    /// a list of options
    pub options: Options<'a>,
}

impl<'a> InterfaceDescription<'a> {
    pub fn block_type() -> u32 {
        BLOCK_TYPE
    }

    pub fn size(&self) -> usize {
        self.options.iter().fold(
            mem::size_of::<u16>() * 2 + mem::size_of::<u32>(),
            |size, opt| size + opt.size(),
        )
    }

    pub fn parse(buf: &'a [u8], endianness: Endianness) -> Result<(&'a [u8], Self)> {
        parse_interface_description(buf, endianness).map_err(|err| PcapError::from(err).into())
    }
}

///     0                   1                   2                   3
///     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///    +---------------------------------------------------------------+
///  0 |                    Block Type = 0x00000001                    |
///    +---------------------------------------------------------------+
///  4 |                      Block Total Length                       |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  8 |           LinkType            |           Reserved            |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// 12 |                            SnapLen                            |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// 16 /                                                               /
///    /                      Options (variable)                       /
///    /                                                               /
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    |                      Block Total Length                       |
///    +---------------------------------------------------------------+
named_args!(parse_interface_description(endianness: Endianness)<InterfaceDescription>,
    do_parse!(
        link_type: u16!(endianness) >>
        reserved: u16!(endianness) >>
        snap_len: u32!(endianness) >>
        options: apply!(parse_options, endianness) >>
        (
            InterfaceDescription {
                link_type,
                reserved,
                snap_len,
                options,
            }
        )
    )
);

pub trait WriteInterfaceDescription {
    fn write_interface_description<'a, T: ByteOrder>(
        &mut self,
        interface_description: &InterfaceDescription<'a>,
    ) -> Result<usize>;
}

impl<W: Write + ?Sized> WriteInterfaceDescription for W {
    fn write_interface_description<'a, T: ByteOrder>(
        &mut self,
        interface_description: &InterfaceDescription<'a>,
    ) -> Result<usize> {
        self.write_u16::<T>(interface_description.link_type)?;
        self.write_u16::<T>(interface_description.reserved)?;
        self.write_u32::<T>(interface_description.snap_len)?;
        self.write_options::<T, _>(&interface_description.options)?;

        Ok(interface_description.size())
    }
}

impl<'a> Block<'a> {
    pub fn as_interface_description(
        &'a self,
        endianness: Endianness,
    ) -> Option<InterfaceDescription<'a>> {
        if self.ty == InterfaceDescription::block_type() {
            InterfaceDescription::parse(&self.body, endianness)
                .map(|(_, interface_description)| interface_description)
                .map_err(|err| {
                    warn!("fail to parse interface description: {:?}", err);

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
    use pcapng::{end_of_opt, Block};

    pub const LE_INTERFACE_DESCRIPTION: &[u8] = b"\x01\x00\x00\x00\
\x5C\x00\x00\x00\
\x01\x00\
\x00\x00\
\x00\x00\x08\x00\
\x02\x00\x03\x00en0\x00\
\x09\x00\x01\x00\x06\x00\x00\x00\
\x0C\x00\x2D\x00Mac OS X 10.13.6, build 17G65 (Darwin 17.7.0)\x00\x00\x00\
\x00\x00\x00\x00\
\x5C\x00\x00\x00";

    lazy_static! {
        static ref INTERFACE_DESCRIPTION: InterfaceDescription<'static> = InterfaceDescription {
            link_type: LinkType::ETHERNET as u16,
            reserved: 0,
            snap_len: 0x080000,
            options: vec![
                if_name("en0"),
                if_tsresol(6),
                if_os("Mac OS X 10.13.6, build 17G65 (Darwin 17.7.0)"),
                end_of_opt(),
            ],
        };
    }

    #[test]
    fn test_parse() {
        let (remaining, block) =
            Block::parse(LE_INTERFACE_DESCRIPTION, Endianness::Little).unwrap();

        assert_eq!(remaining, b"");
        assert_eq!(block.ty, BLOCK_TYPE);
        assert_eq!(block.len as usize, LE_INTERFACE_DESCRIPTION.len());

        let interface_description = block.as_interface_description(Endianness::Little).unwrap();

        assert_eq!(interface_description, *INTERFACE_DESCRIPTION);
    }

    #[test]
    fn test_write() {
        let mut buf = vec![];

        let wrote = buf.write_interface_description::<LittleEndian>(&INTERFACE_DESCRIPTION.clone())
            .unwrap();

        assert_eq!(wrote, INTERFACE_DESCRIPTION.size());
        assert_eq!(
            buf.as_slice(),
            &LE_INTERFACE_DESCRIPTION[8..LE_INTERFACE_DESCRIPTION.len() - 4]
        );
    }
}
