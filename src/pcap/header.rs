use std::io::Write;
use std::mem;

use byteorder::{ByteOrder, NativeEndian, WriteBytesExt};
use nom::*;
use num_traits::FromPrimitive;

use errors::{PcapError, Result};
use pcap::AsEndianness;

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

/// Known identifiers for the types of packets that might be captured in a `pcap` file. This tells
/// you how to interpret the packets you receive.
///
/// Look at [tcpdump.org](http://www.tcpdump.org/linktypes.html) for the canonical list with
/// descriptions.
#[derive(Copy, Clone, Debug, PartialEq, FromPrimitive, ToPrimitive)]
#[repr(u32)]
#[allow(non_camel_case_types)]
pub enum LinkType {
    NULL = 0,
    /// Ethernet packets
    ETHERNET = 1,
    AX25 = 3,
    IEEE802_5 = 6,
    ARCNET_BSD = 7,
    SLIP = 8,
    PPP = 9,
    FDDI = 10,
    PPP_HDLC = 50,
    PPP_ETHER = 51,
    ATM_RFC1483 = 100,
    /// IP packets (IPv4 or IPv6)
    RAW = 101,
    C_HDLC = 104,
    IEEE802_11 = 105,
    FRELAY = 107,
    LOOP = 108,
    LINUX_SLL = 113,
    LTALK = 114,
    PFLOG = 117,
    IEEE802_11_PRISM = 119,
    IP_OVER_FC = 122,
    SUNATM = 123,
    IEEE802_11_RADIOTAP = 127,
    ARCNET_LINUX = 129,
    APPLE_IP_OVER_IEEE1394 = 138,
    MTP2_WITH_PHDR = 139,
    MTP2 = 140,
    MTP3 = 141,
    SCCP = 142,
    DOCSIS = 143,
    LINUX_IRDA = 144,
    USER00_LINKTYPE = 147,
    USER01_LINKTYPE = 148,
    USER02_LINKTYPE = 149,
    USER03_LINKTYPE = 150,
    USER04_LINKTYPE = 151,
    USER05_LINKTYPE = 152,
    USER06_LINKTYPE = 153,
    USER07_LINKTYPE = 154,
    USER08_LINKTYPE = 155,
    USER09_LINKTYPE = 156,
    USER10_LINKTYPE = 157,
    USER11_LINKTYPE = 158,
    USER12_LINKTYPE = 159,
    USER13_LINKTYPE = 160,
    USER14_LINKTYPE = 161,
    USER15_LINKTYPE = 162,
    IEEE802_11_AVS = 163,
    BACNET_MS_TP = 165,
    PPP_PPPD = 166,
    GPRS_LLC = 169,
    GPF_T = 170,
    GPF_F = 171,
    LINUX_LAPD = 177,
    BLUETOOTH_HCI_H4 = 187,
    USB_LINUX = 189,
    PPI = 192,
    IEEE802_15_4 = 195,
    SITA = 196,
    ERF = 197,
    BLUETOOTH_HCI_H4_WITH_PHDR = 201,
    AX25_KISS = 202,
    LAPD = 203,
    PPP_WITH_DIR = 204,
    C_HDLC_WITH_DIR = 205,
    FRELAY_WITH_DIR = 206,
    IPMB_LINUX = 209,
    IEEE802_15_4_NONASK_PHY = 215,
    USB_LINUX_MMAPPED = 220,
    FC_2 = 224,
    FC_2_WITH_FRAME_DELIMS = 225,
    IPNET = 226,
    CAN_SOCKETCAN = 227,
    IPV4 = 228,
    IPV6 = 229,
    IEEE802_15_4_NOFCS = 230,
    DBUS = 231,
    DVB_CI = 235,
    MUX27010 = 236,
    STANAG_5066_D_PDU = 237,
    NFLOG = 239,
    NETANALYZER = 240,
    NETANALYZER_TRANSPARENT = 241,
    IPOIB = 242,
    MPEG_2_TS = 243,
    NG40 = 244,
    NFC_LLCP = 245,
    INFINIBAND = 247,
    SCTP = 248,
    USBPCAP = 249,
    RTAC_SERIAL = 250,
    BLUETOOTH_LE_LL = 251,
    NETLINK = 253,
    BLUETOOTH_LINUX_MONITOR = 254,
    BLUETOOTH_BREDR_BB = 255,
    BLUETOOTH_LE_LL_WITH_PHDR = 256,
    PROFIBUS_DL = 257,
    PKTAP = 258,
    EPON = 259,
    IPMI_HPM_2 = 260,
    ZWAVE_R1_R2 = 261,
    ZWAVE_R3 = 262,
    WATTSTOPPER_DLM = 263,
    ISO_14443 = 264,
    RDS = 265,
    USB_DARWIN = 266,
}

impl Default for LinkType {
    fn default() -> Self {
        LinkType::NULL
    }
}

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
mod test {
    use byteorder::{BigEndian, LittleEndian};

    use pcap::tests::PACKETS;

    use super::*;

    #[test]
    pub fn test_layout() {
        assert_eq!(Header::size(), 24)
    }

    #[test]
    pub fn test_parse_header() {
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
    pub fn test_write_header() {
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
