use std::borrow::Cow;
use std::io::Write;
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr};

use byteorder::{ByteOrder, WriteBytesExt};
use nom::*;

use errors::{PcapError, Result};
use pcapng::options::{opt, pad_to, parse_options, Opt, Options, WriteOptions};
use pcapng::Block;

pub const BLOCK_TYPE: u32 = 0x0000_0004;

pub const NRB_RECORD_END: u16 = 0;
pub const NRB_RECORD_IPV4: u16 = 1;
pub const NRB_RECORD_IPV6: u16 = 2;

pub const NS_DNSNAME: u16 = 2;
pub const NS_DNSIP4ADDR: u16 = 3;
pub const NS_DNSIP6ADDR: u16 = 4;

/// This record delimits the end of name resolution records.
pub fn nrb_record_end<'a>() -> NameRecord<'a> {
    NameRecord::new(NRB_RECORD_END, &[][..])
}

/// This record specifies an IPv4 address, followed by one or more zero-terminated UTF-8 strings
/// containing the DNS entries for that address.
pub fn nrb_record_ipv4<'a, I: IntoIterator<Item = T>, T: AsRef<str>>(
    addr: Ipv4Addr,
    names: I,
) -> NameRecord<'a> {
    let mut buf = addr.octets().to_vec();

    for name in names {
        buf.write_all(name.as_ref().as_bytes()).unwrap();
        buf.push(0);
    }

    NameRecord::new(NRB_RECORD_IPV4, buf)
}

/// This record specifies an IPv6 address, followed by one or more zero-terminated strings
/// containing the DNS entries for that address.
pub fn nrb_record_ipv6<'a, I: IntoIterator<Item = T>, T: AsRef<str>>(
    addr: Ipv6Addr,
    names: I,
) -> NameRecord<'a> {
    let mut buf = addr.octets().to_vec();

    for name in names {
        buf.write_all(name.as_ref().as_bytes()).unwrap();
        buf.push(0);
    }

    NameRecord::new(NRB_RECORD_IPV6, buf)
}

/// This option is a UTF-8 string containing the name of the machine (DNS server) used to perform the name resolution.
pub fn ns_dnsname<T: AsRef<str> + ?Sized>(value: &T) -> Opt {
    opt(NS_DNSNAME, value.as_ref())
}

/// This option specifies the IPv4 address of the DNS server.
pub fn ns_dnsip4addr<'a, T: Into<Ipv4Addr>>(addr: T) -> Opt<'a> {
    Opt::new(NS_DNSIP4ADDR, addr.into().octets().to_vec())
}

/// This option specifies the IPv6 address of the DNS server.
pub fn ns_dnsip6addr<'a, T: Into<Ipv6Addr>>(addr: T) -> Opt<'a> {
    Opt::new(NS_DNSIP6ADDR, addr.into().octets().to_vec())
}

/// The Name Resolution Block (NRB) is used to support the correlation of numeric addresses
/// (present in the captured packets) and their corresponding canonical names and it is optional.
#[derive(Clone, Debug, PartialEq)]
pub struct NameResolution<'a> {
    /// contains an association between a network address and a name.
    pub records: Vec<NameRecord<'a>>,
    /// optionally, a list of options
    pub options: Options<'a>,
}

impl<'a> NameResolution<'a> {
    pub fn block_type() -> u32 {
        BLOCK_TYPE
    }

    pub fn size(&self) -> usize {
        self.records
            .iter()
            .fold(0, |size, record| size + record.size())
            + self.options.iter().fold(0, |size, opt| size + opt.size())
    }

    pub fn parse(buf: &'a [u8], endianness: Endianness) -> Result<(&'a [u8], Self)> {
        parse_name_resolution(buf, endianness).map_err(|err| PcapError::from(err).into())
    }

    /// This option is the name of the machine (DNS server) used to perform the name resolution.
    pub fn dnsname(&self) -> Option<&str> {
        self.options
            .iter()
            .find(|opt| opt.code == NS_DNSNAME)
            .and_then(|opt| opt.as_str())
    }

    /// This option specifies the IPv4 address of the DNS server.
    pub fn dnsip4addr(&self) -> Option<Ipv4Addr> {
        self.options
            .iter()
            .find(|opt| opt.code == NS_DNSIP4ADDR && opt.value.len() == 4)
            .map(|opt| Ipv4Addr::from(*array_ref![opt.value, 0, 4]))
    }

    /// This option specifies the IPv6 address of the DNS server.
    pub fn dnsip6addr(&self) -> Option<Ipv6Addr> {
        self.options
            .iter()
            .find(|opt| opt.code == NS_DNSIP6ADDR && opt.value.len() == 16)
            .map(|opt| Ipv6Addr::from(*array_ref![opt.value, 0, 16]))
    }
}

/// The Name Resolution Record is used to contains an association between a network address and a name.
#[derive(Clone, Debug, PartialEq)]
pub struct NameRecord<'a> {
    /// The code that specifies the type of the current TLV record.
    pub code: u16,
    /// The value of the given record, padded to a 32-bit boundary.
    pub value: Cow<'a, [u8]>,
}

impl<'a> NameRecord<'a> {
    pub fn new<T: Into<Cow<'a, [u8]>>>(code: u16, value: T) -> Self {
        NameRecord {
            code,
            value: value.into(),
        }
    }

    pub fn is_record_end(&self) -> bool {
        self.code == NRB_RECORD_END
    }

    pub fn size(&self) -> usize {
        mem::size_of::<u16>() * 2 + pad_to::<u32>(self.value.len())
    }
}

///     0                   1                   2                   3
///     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///    +---------------------------------------------------------------+
///  0 |                    Block Type = 0x00000004                    |
///    +---------------------------------------------------------------+
///  4 |                      Block Total Length                       |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  8 |      Record Type              |      Record Value Length      |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// 12 /                       Record Value                            /
///    /              variable length, padded to 32 bits               /
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    .                                                               .
///    .                  . . . other records . . .                    .
///    .                                                               .
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    |  Record Type = nrb_record_end |   Record Value Length = 0     |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    /                                                               /
///    /                      Options (variable)                       /
///    /                                                               /
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///    |                      Block Total Length                       |
///    +---------------------------------------------------------------+
named_args!(parse_name_resolution(endianness: Endianness)<NameResolution>,
    dbg_dmp!(do_parse!(
        records: apply!(parse_name_records, endianness) >>
        options: apply!(parse_options, endianness) >>
        (
            NameResolution { records, options }
        )
    ))
);

named_args!(parse_name_records(endianness: Endianness)<Vec<NameRecord>>,
    map!(
        many_till!(
            apply!(parse_name_record, endianness),
            alt!(not!(complete!(non_empty)) | tag!(b"\0\0\0\0") => {|_| ()})
        ),
        |(records, _)| records
    )
);

named_args!(parse_name_record(endianness: Endianness)<NameRecord>,
    do_parse!(
        code: u16!(endianness) >>
        len: u16!(endianness) >>
        value: map!(map!(take!(pad_to::<u32>(len as usize)), |s| &s[..len as usize]), Cow::from) >>
        (
            NameRecord { code, value }
        )
    )
);

pub trait WriteNameRecords {
    fn write_name_record<'a, T: ByteOrder>(&mut self, record: &NameRecord<'a>) -> Result<usize>;

    fn write_name_records<'a, T: ByteOrder, I: IntoIterator<Item = &'a NameRecord<'a>>>(
        &mut self,
        records: I,
    ) -> Result<usize> {
        let mut wrote = 0;
        let mut found_end_of_record = false;

        for record in records {
            wrote += self.write_name_record::<T>(&record)?;

            if record.is_record_end() {
                found_end_of_record = true;
                break;
            }
        }

        if !found_end_of_record {
            wrote += self.write_name_record::<T>(&nrb_record_end())?;
        }

        Ok(wrote)
    }
}

impl<W: Write + ?Sized> WriteNameRecords for W {
    fn write_name_record<'a, T: ByteOrder>(&mut self, record: &NameRecord<'a>) -> Result<usize> {
        self.write_u16::<T>(record.code)?;
        self.write_u16::<T>(record.value.len() as u16)?;
        self.write_all(&record.value)?;

        let padded_len = pad_to::<u32>(record.value.len()) - record.value.len();
        if padded_len > 0 {
            self.write_all(&vec![0; padded_len])?;
        }

        Ok(record.size())
    }
}

pub trait WriteNameResolution {
    fn write_name_resolution<'a, T: ByteOrder>(
        &mut self,
        name_resolution: &NameResolution<'a>,
    ) -> Result<usize>;
}

impl<W: Write + ?Sized> WriteNameResolution for W {
    fn write_name_resolution<'a, T: ByteOrder>(
        &mut self,
        name_resolution: &NameResolution<'a>,
    ) -> Result<usize> {
        self.write_name_records::<T, _>(&name_resolution.records)?;
        self.write_options::<T, _>(&name_resolution.options)?;

        Ok(name_resolution.size())
    }
}

impl<'a> Block<'a> {
    pub fn as_name_resolution(&'a self, endianness: Endianness) -> Option<NameResolution<'a>> {
        if self.ty == NameResolution::block_type() {
            NameResolution::parse(&self.body, endianness)
                .map(|(_, name_resolution)| name_resolution)
                .map_err(|err| {
                    warn!("fail to parse name resolution block: {:?}", err);

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
    use pcapng::Block;

    pub const LE_NAME_RESOLUTION: &[u8] = b"\x04\x00\x00\x00\
\x78\x00\x00\x00\
\x01\x00\x0E\x00\x7F\x00\x00\x01localhost\x00\x00\x00\
\x02\x00\x1A\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01localhost\x00\x00\x00\
\x00\x00\x00\x00\
\x02\x00\x0E\x00our_nameserver\x00\x00\
\x03\x00\x04\x00\x7F\x00\x00\x01\
\x04\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\
\x00\x00\x00\x00\
\x78\x00\x00\x00";

    lazy_static! {
        static ref NAME_RESOLUTION: NameResolution<'static> = NameResolution {
            records: vec![
                nrb_record_ipv4(Ipv4Addr::new(127, 0, 0, 1), vec!["localhost"]),
                nrb_record_ipv6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), vec!["localhost"]),
            ],
            options: vec![
                ns_dnsname("our_nameserver"),
                ns_dnsip4addr(Ipv4Addr::new(127, 0, 0, 1)),
                ns_dnsip6addr(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            ],
        };
    }

    #[test]
    fn test_parse() {
        let (remaining, block) = Block::parse(LE_NAME_RESOLUTION, Endianness::Little).unwrap();

        assert_eq!(remaining, b"");
        assert_eq!(block.ty, BLOCK_TYPE);
        assert_eq!(block.size(), LE_NAME_RESOLUTION.len());

        let name_resolution = block.as_name_resolution(Endianness::Little).unwrap();

        assert_eq!(name_resolution, *NAME_RESOLUTION);
    }

    #[test]
    fn test_write() {
        let mut buf = vec![];

        let wrote = buf
            .write_name_resolution::<LittleEndian>(&NAME_RESOLUTION.clone())
            .unwrap();

        assert_eq!(wrote, NAME_RESOLUTION.size());
        assert_eq!(
            buf.as_slice(),
            &LE_NAME_RESOLUTION[8..LE_NAME_RESOLUTION.len() - 4]
        );
    }
}
