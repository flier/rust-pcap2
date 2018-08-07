use std::io::Write;
use std::mem;

use byteorder::{ByteOrder, WriteBytesExt};
use nom::*;

use errors::{PcapError, Result};
use pcapng::block::Block;
use pcapng::blocks::timestamp::{self, ReadTimestamp, Timestamp};
use pcapng::options::{parse_options, Opt, Options};
use traits::WriteTo;

pub const BLOCK_TYPE: u32 = 0x0000_0005;

pub const ISB_STARTTIME: u16 = 2;
pub const ISB_ENDTIME: u16 = 3;
pub const ISB_IFRECV: u16 = 4;
pub const ISB_IFDROP: u16 = 5;
pub const ISB_FILTERACCEPT: u16 = 6;
pub const ISB_OSDROP: u16 = 7;
pub const ISB_USRDELIV: u16 = 8;

/// This option specifies the time the capture started
pub fn isb_starttime<'a, T: ByteOrder>(ticks: Timestamp) -> Opt<'a> {
    Opt::u64::<T>(
        ISB_STARTTIME,
        (u64::from(ticks as u32) << 32) + (ticks >> 32),
    )
}

/// This option specifies the time the capture ended
pub fn isb_endtime<'a, T: ByteOrder>(ticks: Timestamp) -> Opt<'a> {
    Opt::u64::<T>(ISB_ENDTIME, (u64::from(ticks as u32) << 32) + (ticks >> 32))
}

/// This option specifies the number of packets received from the physical interface
/// starting from the beginning of the capture.
pub fn isb_ifrecv<'a, T: ByteOrder>(count: u64) -> Opt<'a> {
    Opt::u64::<T>(ISB_IFRECV, count)
}

/// This option specifies the number of packets dropped by the interface
/// due to lack of resources starting from the beginning of the capture.
pub fn isb_ifdrop<'a, T: ByteOrder>(count: u64) -> Opt<'a> {
    Opt::u64::<T>(ISB_IFDROP, count)
}

/// This option specifies the number of packets accepted by filter
/// starting from the beginning of the capture.
pub fn isb_filteraccept<'a, T: ByteOrder>(count: u64) -> Opt<'a> {
    Opt::u64::<T>(ISB_FILTERACCEPT, count)
}

/// This option specifies the number of packets
/// dropped by the operating system starting from the beginning of the capture.
pub fn isb_osdrop<'a, T: ByteOrder>(count: u64) -> Opt<'a> {
    Opt::u64::<T>(ISB_OSDROP, count)
}

/// This option specifies the number of packets
/// delivered to the user starting from the beginning of the capture.
pub fn isb_usrdeliv<'a, T: ByteOrder>(count: u64) -> Opt<'a> {
    Opt::u64::<T>(ISB_USRDELIV, count)
}

/// The Interface Statistics Block (ISB) contains the capture statistics for a given interface and it is optional.
#[derive(Clone, Debug, PartialEq)]
pub struct InterfaceStatistics<'a> {
    /// specifies the interface these statistics refers to.
    pub interface_id: u32,
    /// the number of units of time that have elapsed since 1970-01-01 00:00:00 UTC.
    pub timestamp: Timestamp,
    /// optionally, a list of options
    pub options: Options<'a>,
}

impl<'a> InterfaceStatistics<'a> {
    pub fn block_type() -> u32 {
        BLOCK_TYPE
    }

    pub fn size(&self) -> usize {
        self.options
            .iter()
            .fold(mem::size_of::<u32>() * 3, |size, opt| size + opt.size())
    }

    pub fn parse(buf: &'a [u8], endianness: Endianness) -> Result<(&'a [u8], Self)> {
        parse_interface_statistics(buf, endianness).map_err(|err| PcapError::from(err).into())
    }

    /// This option specifies the time the capture started
    pub fn starttime<T: ByteOrder>(&self) -> Option<u64> {
        self.options
            .iter()
            .find(|opt| opt.code == ISB_STARTTIME && opt.value.len() == mem::size_of::<u32>() * 2)
            .and_then(|opt| opt.value.as_ref().read_timestamp::<T>().ok())
    }

    /// This option specifies the time the capture ended
    pub fn endtime<T: ByteOrder>(&self) -> Option<u64> {
        self.options
            .iter()
            .find(|opt| opt.code == ISB_ENDTIME && opt.value.len() == mem::size_of::<u32>() * 2)
            .and_then(|opt| opt.value.as_ref().read_timestamp::<T>().ok())
    }

    /// This option specifies the number of packets received from the physical interface
    /// starting from the beginning of the capture.
    pub fn ifrecv<T: ByteOrder>(&self) -> Option<u64> {
        self.options
            .iter()
            .find(|opt| opt.code == ISB_IFRECV && opt.value.len() == mem::size_of::<u64>())
            .map(|opt| T::read_u64(&opt.value))
    }

    /// This option specifies the number of packets dropped by the interface
    /// due to lack of resources starting from the beginning of the capture.
    pub fn ifdrop<T: ByteOrder>(&self) -> Option<u64> {
        self.options
            .iter()
            .find(|opt| opt.code == ISB_IFDROP && opt.value.len() == mem::size_of::<u64>())
            .map(|opt| T::read_u64(&opt.value))
    }

    /// This option specifies the number of packets accepted by filter
    /// starting from the beginning of the capture.
    pub fn filteraccept<T: ByteOrder>(&self) -> Option<u64> {
        self.options
            .iter()
            .find(|opt| opt.code == ISB_FILTERACCEPT && opt.value.len() == mem::size_of::<u64>())
            .map(|opt| T::read_u64(&opt.value))
    }

    /// This option specifies the number of packets
    /// dropped by the operating system starting from the beginning of the capture.
    pub fn osdrop<T: ByteOrder>(&self) -> Option<u64> {
        self.options
            .iter()
            .find(|opt| opt.code == ISB_OSDROP && opt.value.len() == mem::size_of::<u64>())
            .map(|opt| T::read_u64(&opt.value))
    }

    /// This option specifies the number of packets
    /// delivered to the user starting from the beginning of the capture.
    pub fn usrdeliv<T: ByteOrder>(&self) -> Option<u64> {
        self.options
            .iter()
            .find(|opt| opt.code == ISB_USRDELIV && opt.value.len() == mem::size_of::<u64>())
            .map(|opt| T::read_u64(&opt.value))
    }
}

///     0                   1                   2                   3
///     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///    +---------------------------------------------------------------+
///  0 |                   Block Type = 0x00000005                     |
///    +---------------------------------------------------------------+
///  4 |                      Block Total Length                       |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  8 |                         Interface ID                          |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// 12 |                        Timestamp (High)                       |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// 16 |                        Timestamp (Low)                        |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// 20 /                                                               /
///    /                      Options (variable)                       /
///    /                                                               /
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    |                      Block Total Length                       |
///    +---------------------------------------------------------------+
named_args!(parse_interface_statistics(endianness: Endianness)<InterfaceStatistics>,
    dbg_dmp!(do_parse!(
        interface_id: u32!(endianness) >>
        timestamp_hi: u32!(endianness) >>
        timestamp_lo: u32!(endianness) >>
        options: apply!(parse_options, endianness) >>
        (
            InterfaceStatistics {
                interface_id,
                timestamp: timestamp::new(timestamp_hi, timestamp_lo),
                options,
            }
        )
    ))
);

impl<'a> WriteTo for InterfaceStatistics<'a> {
    fn write_to<T: ByteOrder, W: Write>(&self, w: &mut W) -> Result<usize> {
        w.write_u32::<T>(self.interface_id)?;
        self.timestamp.write_to::<T, _>(w)?;
        self.options.write_to::<T, _>(w)?;

        Ok(self.size())
    }
}

impl<'a> Block<'a> {
    pub fn as_interface_statistics(
        &'a self,
        endianness: Endianness,
    ) -> Option<InterfaceStatistics<'a>> {
        if self.ty == InterfaceStatistics::block_type() {
            InterfaceStatistics::parse(&self.body, endianness)
                .map(|(_, packet)| packet)
                .map_err(|err| {
                    warn!("fail to parse interface statistics: {:?}", err);

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
    use pcapng::{comment, Block};
    use LinkType;

    pub const LE_INTERFACE_STATISTICS: &[u8] = b"\x05\x00\x00\x00\
\x6C\x00\x00\x00\
\x00\x00\x00\x00\
\xAD\x72\x05\x00\xEF\x9E\x23\x23\
\x01\x00\x1C\x00Counters provided by dumpcap\
\x02\x00\x08\x00\xAD\x72\x05\x00\x03\xBD\xEA\x22\
\x03\x00\x08\x00\xAD\x72\x05\x00\xDB\x9E\x23\x23\
\x04\x00\x08\x00\x32\x00\x00\x00\x00\x00\x00\x00\
\x05\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\
\x6C\x00\x00\x00";

    lazy_static! {
        static ref INTERFACE_STATISTICS: InterfaceStatistics<'static> = InterfaceStatistics {
            interface_id: 0,
            timestamp: 0x000572ad_23239eef,
            options: vec![
                comment("Counters provided by dumpcap"),
                isb_starttime::<LittleEndian>(0x000572AD_22EABD03),
                isb_endtime::<LittleEndian>(0x000572AD_23239EDB),
                isb_ifrecv::<LittleEndian>(50),
                isb_ifdrop::<LittleEndian>(0),
            ],
        };
    }

    #[test]
    fn test_parse() {
        let (remaining, block) = Block::parse(LE_INTERFACE_STATISTICS, Endianness::Little).unwrap();

        assert_eq!(remaining, b"");
        assert_eq!(block.ty, BLOCK_TYPE);
        assert_eq!(block.size(), LE_INTERFACE_STATISTICS.len());

        let interface_statistics = block.as_interface_statistics(Endianness::Little).unwrap();

        assert_eq!(interface_statistics, *INTERFACE_STATISTICS);
    }

    #[test]
    fn test_write() {
        let mut buf = vec![];

        let wrote = INTERFACE_STATISTICS
            .write_to::<LittleEndian, _>(&mut buf)
            .unwrap();

        assert_eq!(wrote, INTERFACE_STATISTICS.size());
        assert_eq!(
            buf.as_slice(),
            &LE_INTERFACE_STATISTICS[8..LE_INTERFACE_STATISTICS.len() - 4]
        );
    }

    #[test]
    fn test_options() {
        let interface_statistics = InterfaceStatistics {
            interface_id: 0,
            timestamp: 0,
            options: vec![
                isb_starttime::<LittleEndian>(0x000572AD_22EABD03),
                isb_endtime::<LittleEndian>(0x000572AD_23239EDB),
                isb_ifrecv::<LittleEndian>(123),
                isb_ifdrop::<LittleEndian>(456),
                isb_filteraccept::<LittleEndian>(789),
                isb_osdrop::<LittleEndian>(456),
                isb_usrdeliv::<LittleEndian>(123),
            ],
        };

        let mut buf = vec![];

        interface_statistics
            .write_to::<LittleEndian, _>(&mut buf)
            .unwrap();

        let (_, interface_statistics) =
            InterfaceStatistics::parse(&buf, Endianness::Little).unwrap();

        assert_eq!(
            interface_statistics.starttime::<LittleEndian>().unwrap(),
            0x000572AD_22EABD03
        );
        assert_eq!(
            interface_statistics.endtime::<LittleEndian>().unwrap(),
            0x000572AD_23239EDB
        );
        assert_eq!(interface_statistics.ifrecv::<LittleEndian>().unwrap(), 123);
        assert_eq!(interface_statistics.ifdrop::<LittleEndian>().unwrap(), 456);
        assert_eq!(
            interface_statistics.filteraccept::<LittleEndian>().unwrap(),
            789
        );
        assert_eq!(interface_statistics.osdrop::<LittleEndian>().unwrap(), 456);
        assert_eq!(
            interface_statistics.usrdeliv::<LittleEndian>().unwrap(),
            123
        );
    }
}
