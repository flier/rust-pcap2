use std::io::Write;
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr};

use byteorder::{ByteOrder, WriteBytesExt};
use nom::*;

use errors::{PcapError, Result};
use pcapng::options::{opt, parse_options, Opt, Options};
use pcapng::{Block, BlockType};
use traits::WriteTo;

pub const BLOCK_TYPE: u32 = 0x0000_0001;

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

pub const DEFAULT_TIMESTAMP_RESOLUTION: u64 = 100_0000;

/// This option is a UTF-8 string containing the name of the device used to capture data.
pub fn if_name<T: AsRef<str> + ?Sized>(value: &T) -> Opt {
    opt(IF_NAME, value.as_ref())
}

/// This option is a UTF-8 string containing the description of the device used to capture data.
pub fn if_description<T: AsRef<str> + ?Sized>(value: &T) -> Opt {
    opt(IF_DESCRIPTION, value.as_ref())
}

/// This option s an IPv4 network address and corresponding netmask for the interface.
pub fn if_ipv4addr<'a, T: Into<Ipv4Addr>>(addr: T, mask: T) -> Opt<'a> {
    let mut buf = addr.into().octets().to_vec();

    buf.write_all(&mask.into().octets()[..]).unwrap();

    Opt::new(IF_IPV4ADDR, buf)
}

/// This option is an IPv6 network address and corresponding prefix length for the interface.
pub fn if_ipv6addr<'a, T: Into<Ipv6Addr>>(addr: T, prefix: u8) -> Opt<'a> {
    let mut buf = addr.into().octets().to_vec();

    buf.push(prefix);

    Opt::new(IF_IPV6ADDR, buf)
}

pub type MacAddr = [u8; 6];

/// This option is the Interface Hardware MAC address (48 bits), if available.
pub fn if_macaddr<'a>(addr: MacAddr) -> Opt<'a> {
    Opt::new(IF_MACADDR, addr.to_vec())
}

pub type EuiAddr = [u8; 8];

/// This option is the Interface Hardware EUI address (64 bits), if available.
pub fn if_euiaddr<'a>(addr: EuiAddr) -> Opt<'a> {
    Opt::new(IF_EUIADDR, addr.to_vec())
}

/// This option is a 64-bit number for the Interface speed (in bits per second).
pub fn if_speed<'a, T: ByteOrder>(value: u64) -> Opt<'a> {
    Opt::u64::<T>(IF_SPEED, value)
}

/// This option identifies the resolution of timestamps.
pub fn if_tsresol<'a>(resolution: u64) -> Opt<'a> {
    Opt::new(
        IF_TSRESOL,
        vec![if resolution.is_power_of_two() {
            (resolution.trailing_zeros() as u8) | 0x80
        } else {
            (resolution as f64).log10().round() as u8
        }],
    )
}

/// This option identifies the time zone for GMT support.
pub fn if_tzone<'a, T: ByteOrder>(tzone: u32) -> Opt<'a> {
    Opt::u32::<T>(IF_TZONE, tzone)
}

/// This option identifies the filter (e.g. "capture only TCP traffic") used to capture traffic.
pub fn if_filter<T: AsRef<str> + ?Sized>(value: &T) -> Opt {
    opt(IF_FILTER, value.as_ref())
}

/// This  option is a UTF-8 string containing the name of the operating system of the machine
/// in which this interface is installed.
pub fn if_os<T: AsRef<str> + ?Sized>(value: &T) -> Opt {
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
    pub fn block_type() -> BlockType {
        BlockType::InterfaceDescription
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

    pub fn name(&self) -> Option<&str> {
        self.options
            .iter()
            .find(|opt| opt.code == IF_NAME)
            .and_then(|opt| opt.as_str())
    }

    pub fn description(&self) -> Option<&str> {
        self.options
            .iter()
            .find(|opt| opt.code == IF_DESCRIPTION)
            .and_then(|opt| opt.as_str())
    }

    pub fn ipv4addr(&self) -> Vec<(Ipv4Addr, Ipv4Addr)> {
        self.options
            .iter()
            .filter(|opt| opt.code == IF_IPV4ADDR && opt.value.len() == mem::size_of::<u32>() * 2)
            .map(|opt| {
                (
                    Ipv4Addr::from(*array_ref![opt.value, 0, 4]),
                    Ipv4Addr::from(*array_ref![opt.value, 4, 4]),
                )
            })
            .collect()
    }

    pub fn ipv6addr(&self) -> Vec<(Ipv6Addr, u8)> {
        self.options
            .iter()
            .filter(|opt| opt.code == IF_IPV6ADDR && opt.value.len() == 17)
            .map(|opt| (Ipv6Addr::from(*array_ref![opt.value, 0, 16]), opt.value[16]))
            .collect()
    }

    pub fn macaddr(&self) -> Option<&MacAddr> {
        self.options
            .iter()
            .find(|opt| opt.code == IF_MACADDR && opt.value.len() == 6)
            .map(|opt| array_ref![opt.value, 0, 6])
    }

    pub fn euiaddr(&self) -> Option<&EuiAddr> {
        self.options
            .iter()
            .find(|opt| opt.code == IF_EUIADDR && opt.value.len() == 8)
            .map(|opt| array_ref![opt.value, 0, 8])
    }

    pub fn speed<T: ByteOrder>(&self) -> Option<u64> {
        self.options
            .iter()
            .find(|opt| opt.code == IF_SPEED && opt.value.len() == mem::size_of::<u64>())
            .map(|opt| T::read_u64(&opt.value))
    }

    pub fn tsresol(&self) -> Option<u64> {
        self.options
            .iter()
            .find(|opt| opt.code == IF_TSRESOL && opt.value.len() == 1)
            .map(|opt| {
                let n = opt.value[0];

                if (n & 0x80) == 0x80 {
                    let tsresol_shift = n & 0x7F;

                    if tsresol_shift < 64 {
                        1 << tsresol_shift
                    } else {
                        DEFAULT_TIMESTAMP_RESOLUTION
                    }
                } else {
                    let tsresol_opt = n as i8;

                    if tsresol_opt < 20 {
                        10u64.pow(tsresol_opt as u32)
                    } else {
                        DEFAULT_TIMESTAMP_RESOLUTION
                    }
                }
            })
    }

    pub fn tzone<T: ByteOrder>(&self) -> Option<u32> {
        self.options
            .iter()
            .find(|opt| opt.code == IF_TZONE && opt.value.len() == mem::size_of::<u32>())
            .map(|opt| T::read_u32(&opt.value))
    }

    pub fn filter(&self) -> Option<&str> {
        self.options
            .iter()
            .find(|opt| opt.code == IF_FILTER)
            .and_then(|opt| opt.as_str())
    }

    pub fn os(&self) -> Option<&str> {
        self.options
            .iter()
            .find(|opt| opt.code == IF_OS)
            .and_then(|opt| opt.as_str())
    }

    pub fn fcslen(&self) -> Option<u8> {
        self.options
            .iter()
            .find(|opt| opt.code == IF_FCSLEN && opt.value.len() == 1)
            .map(|opt| opt.value[0])
    }

    pub fn tsoffset<T: ByteOrder>(&self) -> Option<u64> {
        self.options
            .iter()
            .find(|opt| opt.code == IF_TSOFFSET && opt.value.len() == mem::size_of::<u64>())
            .map(|opt| T::read_u64(&opt.value))
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

impl<'a> WriteTo for InterfaceDescription<'a> {
    fn write_to<T: ByteOrder, W: Write>(&self, w: &mut W) -> Result<usize> {
        w.write_u16::<T>(self.link_type)?;
        w.write_u16::<T>(self.reserved)?;
        w.write_u32::<T>(self.snap_len)?;
        self.options.write_to::<T, _>(w)?;

        Ok(self.size())
    }
}

impl<'a> Block<'a> {
    pub fn is_interface_description(&self) -> bool {
        self.ty == BLOCK_TYPE
    }

    pub fn as_interface_description(
        &'a self,
        endianness: Endianness,
    ) -> Option<InterfaceDescription<'a>> {
        if self.is_interface_description() {
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
pub mod tests {
    use byteorder::LittleEndian;

    use super::*;
    use pcapng::Block;
    use LinkType;

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
                if_tsresol(1000000),
                if_os("Mac OS X 10.13.6, build 17G65 (Darwin 17.7.0)"),
            ],
        };
    }

    #[test]
    fn test_parse() {
        let (remaining, block) =
            Block::parse(LE_INTERFACE_DESCRIPTION, Endianness::Little).unwrap();

        assert_eq!(remaining, b"");
        assert_eq!(block.ty, BLOCK_TYPE);
        assert_eq!(block.size(), LE_INTERFACE_DESCRIPTION.len());

        let interface_description = block.as_interface_description(Endianness::Little).unwrap();

        assert_eq!(interface_description, *INTERFACE_DESCRIPTION);
    }

    #[test]
    fn test_write() {
        let mut buf = vec![];

        let wrote = INTERFACE_DESCRIPTION
            .write_to::<LittleEndian, _>(&mut buf)
            .unwrap();

        assert_eq!(wrote, INTERFACE_DESCRIPTION.size());
        assert_eq!(
            buf.as_slice(),
            &LE_INTERFACE_DESCRIPTION[8..LE_INTERFACE_DESCRIPTION.len() - 4]
        );
    }

    #[test]
    fn test_options() {
        let interface_description = InterfaceDescription {
            link_type: LinkType::ETHERNET as u16,
            reserved: 0,
            snap_len: 0x080000,
            options: vec![
                if_name("en0"),
                if_description("Broadcom NetXtreme"),
                if_ipv4addr(Ipv4Addr::new(127, 0, 0, 1), Ipv4Addr::new(255, 255, 255, 0)),
                if_ipv6addr(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), 64),
                if_macaddr([0x00, 0x01, 0x02, 0x03, 0x04, 0x05]),
                if_euiaddr([0x02, 0x34, 0x56, 0xFF, 0xFE, 0x78, 0x9A, 0xBC]),
                if_speed::<LittleEndian>(100000000),
                if_tsresol(1024),
                if_tzone::<LittleEndian>(8),
                if_filter("tcp port 23 and host 192.0.2.5"),
                if_os("Mac OS X 10.13.6, build 17G65 (Darwin 17.7.0)"),
                if_fcslen(4),
                if_tsoffset::<LittleEndian>(1234),
            ],
        };

        let mut buf = vec![];

        interface_description
            .write_to::<LittleEndian, _>(&mut buf)
            .unwrap();

        let (_, interface_description) =
            InterfaceDescription::parse(&buf, Endianness::Little).unwrap();

        assert_eq!(interface_description.name().unwrap(), "en0");
        assert_eq!(
            interface_description.description().unwrap(),
            "Broadcom NetXtreme"
        );
        assert_eq!(
            interface_description.ipv4addr(),
            vec![(Ipv4Addr::new(127, 0, 0, 1), Ipv4Addr::new(255, 255, 255, 0))]
        );
        assert_eq!(
            interface_description.ipv6addr(),
            vec![(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), 64)]
        );
        assert_eq!(
            interface_description.macaddr().unwrap(),
            &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05]
        );
        assert_eq!(
            interface_description.euiaddr().unwrap(),
            &[0x02, 0x34, 0x56, 0xFF, 0xFE, 0x78, 0x9A, 0xBC]
        );
        assert_eq!(
            interface_description.speed::<LittleEndian>().unwrap(),
            100000000
        );
        assert_eq!(interface_description.tsresol().unwrap(), 1024);
        assert_eq!(interface_description.tzone::<LittleEndian>().unwrap(), 8);
        assert_eq!(
            interface_description.filter().unwrap(),
            "tcp port 23 and host 192.0.2.5"
        );
        assert_eq!(
            interface_description.os().unwrap(),
            "Mac OS X 10.13.6, build 17G65 (Darwin 17.7.0)"
        );
        assert_eq!(interface_description.fcslen().unwrap(), 4);
        assert_eq!(
            interface_description.tsoffset::<LittleEndian>().unwrap(),
            1234
        );
    }
}
