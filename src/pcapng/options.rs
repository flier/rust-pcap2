use std::borrow::Cow;
use std::io::{BufReader, Read, Write};
use std::mem;
use std::str;

use byteorder::{ByteOrder, WriteBytesExt};
use failure::Error;
use nom::*;

use errors::{PcapError, Result};
use traits::WriteTo;

/// This option delimits the end of the optional fields.
pub const OPT_ENDOFOPT: u16 = 0;

/// This option is a UTF-8 string containing human-readable comment text
/// that is associated to the current block.
pub const OPT_COMMENT: u16 = 1;

/// This option code identifies a Custom Option containing a UTF-8 string
/// in the Custom Data portion, without NULL termination.
///
/// This Custom Option can be safely copied to a new file if the pcapng file is manipulated by an application;
/// otherwise 19372 should be used instead. See Section 6.2 for details.
pub const OPT_CUSTOM_STR: u16 = 2988;

/// This option code identifies a Custom Option containing binary octets in the Custom Data portion.
///
/// This Custom Option can be safely copied to a new file if the pcapng file is manipulated by an application;
/// otherwise 19372 should be used instead. See Section 6.2 for details.
pub const OPT_CUSTOM_BYTES: u16 = 2989;

/// This option code identifies a Custom Option containing a UTF-8 string
/// in the Custom Data portion, without NULL termination.
///
/// This Custom Option should not be copied to a new file if the pcapng file is manipulated by an application.
/// See Section 6.2 for details.
pub const OPT_CUSTOM_PRIVATE_STR: u16 = 19372;

/// This option code identifies a Custom Option containing binary octets in the Custom Data portion.
///
/// This Custom Option should not be copied to a new file if the pcapng file is manipulated by an application.
/// See Section 6.2 for details.
pub const OPT_CUSTOM_PRIVATE_BYTES: u16 = 19373;

pub type Options<'a> = Vec<Opt<'a>>;

pub trait ReadOptions<'a> {
    fn read_options(&mut self, endianness: Endianness) -> Result<Options<'a>>;
}

impl<'a> ReadOptions<'a> for &'a [u8] {
    fn read_options(&mut self, endianness: Endianness) -> Result<Options<'a>> {
        let (remaining, options) =
            parse_options(self, endianness).map_err(|err| Error::from(PcapError::from(err)))?;

        *self = remaining;

        Ok(options)
    }
}

impl<'a, R: Read> ReadOptions<'a> for BufReader<R> {
    fn read_options(&mut self, endianness: Endianness) -> Result<Options<'a>> {
        let mut options = vec![];

        loop {
            let hdr_len = mem::size_of::<u16>() * 2;
            let mut buf = vec![0; hdr_len];

            self.read_exact(&mut buf)?;

            let (code, opt_len) = u16!(&buf, endianness)
                .and_then(|(remaining, code)| {
                    u16!(remaining, endianness).map(|(_, len)| (code, len as usize))
                })
                .map_err(|err| Error::from(PcapError::from(err)))?;

            if code == OPT_ENDOFOPT {
                break;
            }

            let mut buf = vec![0; pad_to::<u32>(opt_len)];

            self.read_exact(&mut buf)?;

            buf.split_off(opt_len);

            options.push(Opt::new(code, buf))
        }

        Ok(options)
    }
}

impl<'a> WriteTo for Options<'a> {
    fn write_to<T: ByteOrder, W: Write>(&self, w: &mut W) -> Result<usize> {
        let mut wrote = 0;
        let mut found_end_of_opt = false;

        for opt in self {
            wrote += opt.write_to::<T, W>(w)?;

            if opt.is_end_of_opt() {
                found_end_of_opt = true;
                break;
            }
        }

        if wrote > 0 && !found_end_of_opt {
            wrote += end_of_opt().write_to::<T, W>(w)?;
        }

        Ok(wrote)
    }
}

impl<'a> WriteTo for Opt<'a> {
    fn write_to<T: ByteOrder, W: Write>(&self, w: &mut W) -> Result<usize> {
        w.write_u16::<T>(self.code)?;
        w.write_u16::<T>(self.value.len() as u16)?;
        w.write_all(&self.value)?;

        let padded_len = pad_to::<u32>(self.value.len()) - self.value.len();
        if padded_len > 0 {
            w.write_all(&vec![0; padded_len])?;
        }

        Ok(self.size())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Opt<'a> {
    /// The code that specifies the type of the current TLV record.
    pub code: u16,
    /// The value of the given option, padded to a 32-bit boundary.
    pub value: Cow<'a, [u8]>,
}

pub fn opt<T: AsRef<[u8]> + ?Sized>(code: u16, value: &T) -> Opt {
    Opt::new(code, value.as_ref())
}

pub fn end_of_opt<'a>() -> Opt<'a> {
    Opt::new(OPT_ENDOFOPT, &[][..])
}

pub fn comment(value: &str) -> Opt {
    Opt::new(OPT_COMMENT, value.as_bytes())
}

pub fn custom_str<T: ByteOrder>(private_enterprise_number: u32, value: &str) -> Opt {
    Opt::custom::<T, _>(OPT_CUSTOM_STR, private_enterprise_number, value)
}

pub fn custom_bytes<T: ByteOrder>(private_enterprise_number: u32, value: &[u8]) -> Opt {
    Opt::custom::<T, _>(OPT_CUSTOM_BYTES, private_enterprise_number, value)
}

pub fn custom_private_str<T: ByteOrder>(private_enterprise_number: u32, value: &str) -> Opt {
    Opt::custom::<T, _>(OPT_CUSTOM_PRIVATE_STR, private_enterprise_number, value)
}

pub fn custom_private_bytes<T: ByteOrder>(private_enterprise_number: u32, value: &[u8]) -> Opt {
    Opt::custom::<T, _>(OPT_CUSTOM_PRIVATE_BYTES, private_enterprise_number, value)
}

impl<'a> Opt<'a> {
    pub fn new<T: Into<Cow<'a, [u8]>>>(code: u16, value: T) -> Opt<'a> {
        Opt {
            code,
            value: value.into(),
        }
    }

    pub fn custom<T: ByteOrder, V: AsRef<[u8]>>(
        code: u16,
        private_enterprise_number: u32,
        value: V,
    ) -> Opt<'a> {
        let mut buf = vec![];

        buf.write_u32::<T>(private_enterprise_number).unwrap();
        buf.write_all(value.as_ref()).unwrap();

        Opt::new(code, buf)
    }

    pub fn u64<T: ByteOrder>(code: u16, value: u64) -> Opt<'a> {
        let mut buf = vec![0; mem::size_of::<u64>()];

        T::write_u64(&mut buf, value);

        Opt::new(code, buf)
    }

    pub fn u32<T: ByteOrder>(code: u16, value: u32) -> Opt<'a> {
        let mut buf = vec![0; mem::size_of::<u32>()];

        T::write_u32(&mut buf, value);

        Opt::new(code, buf)
    }

    pub fn size(&self) -> usize {
        mem::size_of::<u16>() * 2 + pad_to::<u32>(self.value.len())
    }

    pub fn parse(buf: &'a [u8], endianness: Endianness) -> Result<(&[u8], Self)> {
        parse_opt(buf, endianness).map_err(|err| PcapError::from(err).into())
    }

    pub fn as_str(&self) -> Option<&str> {
        str::from_utf8(&self.value).ok()
    }

    pub fn is_end_of_opt(&self) -> bool {
        self.code == OPT_ENDOFOPT
    }

    pub fn as_comment(&self) -> Option<&str> {
        if self.code == OPT_COMMENT {
            str::from_utf8(&self.value).ok()
        } else {
            None
        }
    }

    pub fn as_custom_str<T: ByteOrder>(&self) -> Option<(u32, &str)> {
        if self.code == OPT_CUSTOM_STR && self.value.len() > mem::size_of::<u32>() {
            str::from_utf8(&self.value[mem::size_of::<u32>()..])
                .ok()
                .map(|s| (T::read_u32(&self.value), s))
        } else {
            None
        }
    }

    pub fn as_custom_bytes<T: ByteOrder>(&self) -> Option<(u32, &[u8])> {
        if self.code == OPT_CUSTOM_BYTES && self.value.len() > mem::size_of::<u32>() {
            Some((
                T::read_u32(&self.value),
                &self.value[mem::size_of::<u32>()..],
            ))
        } else {
            None
        }
    }

    pub fn as_custom_private_str<T: ByteOrder>(&self) -> Option<(u32, &str)> {
        if self.code == OPT_CUSTOM_PRIVATE_STR && self.value.len() > mem::size_of::<u32>() {
            str::from_utf8(&self.value[mem::size_of::<u32>()..])
                .ok()
                .map(|s| (T::read_u32(&self.value), s))
        } else {
            None
        }
    }
    pub fn as_custom_private_bytes<T: ByteOrder>(&self) -> Option<(u32, &[u8])> {
        if self.code == OPT_CUSTOM_PRIVATE_BYTES && self.value.len() > mem::size_of::<u32>() {
            Some((
                T::read_u32(&self.value),
                &self.value[mem::size_of::<u32>()..],
            ))
        } else {
            None
        }
    }
}

/// The option list is terminated by a option which uses the special 'End of Option' code (opt_endofopt).
/// Code that writes pcapng files MUST put an opt_endofopt option at the end of an option list.
/// Code that reads pcapng files MUST NOT assume an option list will have an opt_endofopt option at the end;
/// it MUST also check for the end of the block, and SHOULD treat blocks
/// where the option list has no opt_endofopt option as if the option list had an opt_endofopt option at the end.
///
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |      Option Code              |         Option Length         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// /                       Option Value                            /
/// /              variable length, padded to 32 bits               /
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// /                                                               /
/// /                 . . . other options . . .                     /
/// /                                                               /
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Option Code == opt_endofopt  |  Option Length == 0          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
/// Customs Options are used for portable, vendor-specific data related to the block they're in.
/// A Custom Option can be in any block type that can have options, can be repeated any number of times in a block,
/// and may come before or after other option types - except the opt_endofopt which is always the last option.
/// Different Custom Options, of different type codes and/or different Private Enterprise Numbers,
/// may be used in the same pcapng file. See Section 6 for additional details.
///
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Custom Option Code        |         Option Length         |
/// +---------------------------------------------------------------+
/// |                Private Enterprise Number (PEN)                |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// /                        Custom Data                            /
/// /              variable length, padded to 32 bits               /
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

named_args!(pub parse_options<'a>(endianness: Endianness)<&'a [u8], Options<'a>>,
    map!(
        many_till!(
            apply!(parse_opt, endianness),
            alt!(not!(complete!(non_empty)) | tag!(b"\0\0\0\0") => {|_| ()})
        ),
        |(options, _)| options
    )
);

named_args!(parse_opt(endianness: Endianness)<Opt>,
    do_parse!(
        code: u16!(endianness) >>
        len: u16!(endianness) >>
        value: map!(map!(take!(pad_to::<u32>(len as usize)), |s| &s[..len as usize]), Cow::from) >>
        (
            Opt { code, value }
        )
    )
);

pub fn pad_to<T>(size: usize) -> usize {
    let pad_size = mem::size_of::<T>();

    ((size + pad_size - 1) / pad_size) * pad_size
}

#[cfg(test)]
mod tests {
    use byteorder::LittleEndian;

    use super::*;
    use pcapng::{shb_os, shb_userappl};

    #[test]
    pub fn test_size() {
        assert_eq!(end_of_opt().size(), 4);
        assert_eq!(comment("test").size(), 8);
        assert_eq!(comment("foo").size(), 8);
        assert_eq!(custom_str::<LittleEndian>(123, "test").size(), 12);
        assert_eq!(custom_bytes::<LittleEndian>(123, b"foo").size(), 12);
        assert_eq!(custom_private_str::<LittleEndian>(123, "test").size(), 12);
        assert_eq!(custom_private_bytes::<LittleEndian>(123, b"foo").size(), 12);
    }

    lazy_static! {
        static ref OPTIONS: Vec<Opt<'static>> = vec![
            shb_os("Windows XP"),
            shb_userappl("Test004.exe"),
            custom_str::<LittleEndian>(123, "github.com"),
            comment("foo"),
            opt(123, "bar"),
        ];
    }

    const LE_OPTIONS: &[u8] = b"\x03\0\x0a\0Windows XP\0\0\
    \x04\0\x0b\0Test004.exe\0\
    \xac\x0b\x0e\0\x7b\0\0\0github.com\0\0\
    \x01\0\x03\0foo\0\
    \x7b\0\x03\0bar\0\
    \0\0\0\0";

    #[test]
    fn test_parse() {
        let mut input = &LE_OPTIONS[..];

        let options = input.read_options(Endianness::Little).unwrap();

        assert_eq!(options, *OPTIONS);
    }

    #[test]
    fn test_parse_empty() {
        assert_eq!(
            parse_options(&[][..], Endianness::Little).unwrap(),
            (&[][..], vec![])
        );
    }

    #[test]
    fn test_read() {
        let mut input = BufReader::new(&LE_OPTIONS[..]);

        let options = input.read_options(Endianness::Little).unwrap();

        assert_eq!(options, *OPTIONS);
    }

    #[test]
    fn test_write() {
        let mut buf = vec![];

        assert_eq!(
            OPTIONS.write_to::<LittleEndian, _>(&mut buf).unwrap(),
            LE_OPTIONS.len()
        );
        assert_eq!(buf.as_slice(), &LE_OPTIONS[..]);
    }
}
