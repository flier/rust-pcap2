use std::borrow::Cow;
use std::io::{BufReader, Read, Write};
use std::mem;
use std::str;

use byteorder::{ByteOrder, WriteBytesExt};
use failure::Error;
use nom::*;

use errors::{PcapError, Result};

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

            options.push(match code {
                OPT_CUSTOM_STR
                | OPT_CUSTOM_BYTES
                | OPT_CUSTOM_PRIVATE_STR
                | OPT_CUSTOM_PRIVATE_BYTES => {
                    let value = buf.split_off(mem::size_of::<u32>());
                    let pen = u32!(&buf, endianness).map(|(_, pen)| pen).ok();
                    Opt {
                        code,
                        len: opt_len as u16,
                        pen,
                        value: value.into(),
                    }
                }
                _ => Opt {
                    code,
                    len: opt_len as u16,
                    pen: None,
                    value: buf.into(),
                },
            })
        }

        Ok(options)
    }
}

pub trait WriteOptions {
    fn write_option<'a, T: ByteOrder>(&mut self, opt: &Opt<'a>) -> Result<usize>;

    fn write_options<'a, T: ByteOrder, I: IntoIterator<Item = &'a Opt<'a>>>(
        &mut self,
        options: I,
    ) -> Result<usize> {
        let mut wrote = 0;
        let mut found_end_of_opt = false;

        for opt in options {
            wrote += self.write_option::<T>(&opt)?;

            if opt.is_end_of_opt() {
                found_end_of_opt = true;
                break;
            }
        }

        if wrote > 0 && !found_end_of_opt {
            wrote += self.write_option::<T>(&end_of_opt())?;
        }

        Ok(wrote)
    }
}

impl<W: Write + ?Sized> WriteOptions for W {
    fn write_option<'a, T: ByteOrder>(&mut self, opt: &Opt<'a>) -> Result<usize> {
        self.write_u16::<T>(opt.code)?;
        self.write_u16::<T>(opt.len)?;
        if let Some(pen) = opt.pen {
            self.write_u32::<T>(pen)?;
        }
        self.write(&opt.value)?;

        let padded_len = pad_to::<u32>(opt.value.len()) - opt.value.len();
        if padded_len > 0 {
            self.write(&vec![0; padded_len])?;
        }

        Ok(opt.size())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Opt<'a> {
    /// The code that specifies the type of the current TLV record.
    pub code: u16,
    /// The actual length of the following 'Option Value' field without the padding octets.
    pub len: u16,
    /// An IANA-assigned Private Enterprise Number identifying the organization which defined the Custom Option.
    pub pen: Option<u32>,
    /// The value of the given option, padded to a 32-bit boundary.
    pub value: Cow<'a, [u8]>,
}

pub fn opt<'a, T: AsRef<[u8]> + ?Sized>(code: u16, value: &'a T) -> Opt<'a> {
    Opt::new(code, value.as_ref())
}

pub fn end_of_opt<'a>() -> Opt<'a> {
    Opt::new(OPT_ENDOFOPT, &[][..])
}

pub fn comment<'a>(value: &'a str) -> Opt<'a> {
    Opt::new(OPT_COMMENT, value.as_bytes())
}

pub fn custom_str<'a>(private_enterprise_number: u32, value: &'a str) -> Opt<'a> {
    Opt::custom(OPT_CUSTOM_STR, private_enterprise_number, value)
}

pub fn custom_bytes<'a>(private_enterprise_number: u32, value: &'a [u8]) -> Opt<'a> {
    Opt::custom(OPT_CUSTOM_BYTES, private_enterprise_number, value)
}

pub fn custom_private_str<'a>(private_enterprise_number: u32, value: &'a str) -> Opt<'a> {
    Opt::custom(OPT_CUSTOM_PRIVATE_STR, private_enterprise_number, value)
}

pub fn custom_private_bytes<'a>(private_enterprise_number: u32, value: &'a [u8]) -> Opt<'a> {
    Opt::custom(OPT_CUSTOM_PRIVATE_BYTES, private_enterprise_number, value)
}

impl<'a> Opt<'a> {
    pub fn new<T: Into<Cow<'a, [u8]>>>(code: u16, value: T) -> Opt<'a> {
        let value = value.into();

        Opt {
            code,
            len: value.len() as u16,
            pen: None,
            value: value.into(),
        }
    }

    pub fn from_iter<T: IntoIterator<Item = u8>>(code: u16, iter: T) -> Self {
        let value = iter.into_iter().collect::<Vec<u8>>();

        Opt {
            code,
            len: value.len() as u16,
            pen: None,
            value: value.into(),
        }
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

    pub fn custom<T: AsRef<[u8]> + ?Sized>(
        code: u16,
        private_enterprise_number: u32,
        value: &'a T,
    ) -> Opt<'a> {
        let buf = value.as_ref();

        Opt {
            code,
            len: (mem::size_of::<u32>() + buf.len()) as u16,
            pen: Some(private_enterprise_number),
            value: buf.into(),
        }
    }

    pub fn size(&self) -> usize {
        mem::size_of::<u16>() * 2
            + self.pen.map_or(0, |_| mem::size_of::<u32>())
            + pad_to::<u32>(self.value.len())
    }

    pub fn parse(buf: &'a [u8], endianness: Endianness) -> Result<(&[u8], Self)> {
        parse_opt(buf, endianness).map_err(|err| PcapError::from(err).into())
    }

    pub fn value(&self) -> &[u8] {
        if self.len as usize <= self.value.len() {
            &self.value[..self.len as usize]
        } else {
            &self.value
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        str::from_utf8(&self.value).ok()
    }

    pub fn is_end_of_opt(&self) -> bool {
        self.code == OPT_ENDOFOPT
    }

    pub fn as_comment(&self) -> Option<&str> {
        if self.code == OPT_COMMENT {
            str::from_utf8(self.value()).ok()
        } else {
            None
        }
    }

    pub fn as_custom_str(&self) -> Option<(u32, &str)> {
        if self.code == OPT_CUSTOM_STR {
            str::from_utf8(self.value())
                .ok()
                .and_then(|s| self.pen.map(|pen| (pen, s)))
        } else {
            None
        }
    }

    pub fn as_custom_bytes(&self) -> Option<(u32, &[u8])> {
        if self.code == OPT_CUSTOM_BYTES {
            self.pen.map(|pen| (pen, self.value()))
        } else {
            None
        }
    }

    pub fn as_custom_private_str(&self) -> Option<(u32, &str)> {
        if self.code == OPT_CUSTOM_PRIVATE_STR {
            str::from_utf8(self.value())
                .ok()
                .and_then(|s| self.pen.map(|pen| (pen, s)))
        } else {
            None
        }
    }
    pub fn as_custom_private_bytes(&self) -> Option<(u32, &[u8])> {
        if self.code == OPT_CUSTOM_PRIVATE_BYTES {
            self.pen.map(|pen| (pen, self.value()))
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
        opt_len: u16!(endianness) >>
        pen: switch!(value!(code),
            OPT_CUSTOM_STR              => map!(u32!(endianness), Some) |
            OPT_CUSTOM_BYTES            => map!(u32!(endianness), Some) |
            OPT_CUSTOM_PRIVATE_STR      => map!(u32!(endianness), Some) |
            OPT_CUSTOM_PRIVATE_BYTES    => map!(u32!(endianness), Some) |
            _                           => value!(None)
        ) >>
        val_len: value!(opt_len as usize - pen.map_or(0, |_| mem::size_of::<u32>())) >>
        value: map!(map!(take!(pad_to::<u32>(val_len)), |s| &s[..val_len]), Cow::from) >>
        (
            Opt { code, len: opt_len as u16, pen, value }
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
        assert_eq!(custom_str(123, "test").size(), 12);
        assert_eq!(custom_bytes(123, b"foo").size(), 12);
        assert_eq!(custom_private_str(123, "test").size(), 12);
        assert_eq!(custom_private_bytes(123, b"foo").size(), 12);
    }

    lazy_static! {
        static ref OPTIONS: Vec<Opt<'static>> = vec![
            shb_os("Windows XP"),
            shb_userappl("Test004.exe"),
            custom_str(123, "github.com"),
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
            buf.write_options::<LittleEndian, _>(OPTIONS.iter())
                .unwrap(),
            LE_OPTIONS.len()
        );
        assert_eq!(buf.as_slice(), &LE_OPTIONS[..]);
    }
}
