use std::borrow::Cow;
use std::io::{BufReader, Read};
use std::mem;
use std::result::Result as StdResult;
use std::str;

use failure::Error;
use nom::*;
use num_traits::FromPrimitive;

use errors::{PcapError, Result};

#[derive(Copy, Clone, Debug, PartialEq, FromPrimitive, ToPrimitive)]
#[repr(u16)]
pub enum Code {
    /// This option delimits the end of the optional fields.
    EndOfOpt = 0,

    /// This option is a UTF-8 string containing human-readable comment text
    /// that is associated to the current block.
    Comment = 1,

    /// This option code identifies a Custom Option containing a UTF-8 string
    /// in the Custom Data portion, without NULL termination.
    ///
    /// This Custom Option can be safely copied to a new file if the pcapng file is manipulated by an application;
    /// otherwise 19372 should be used instead. See Section 6.2 for details.
    CustomStr = 2988,

    /// This option code identifies a Custom Option containing binary octets in the Custom Data portion.
    ///
    /// This Custom Option can be safely copied to a new file if the pcapng file is manipulated by an application;
    /// otherwise 19372 should be used instead. See Section 6.2 for details.
    CustomBytes = 2989,

    /// This option code identifies a Custom Option containing a UTF-8 string
    /// in the Custom Data portion, without NULL termination.
    ///
    /// This Custom Option should not be copied to a new file if the pcapng file is manipulated by an application.
    /// See Section 6.2 for details.
    CustomPrivateStr = 19372,

    /// This option code identifies a Custom Option containing binary octets in the Custom Data portion.
    ///
    /// This Custom Option should not be copied to a new file if the pcapng file is manipulated by an application.
    /// See Section 6.2 for details.
    CustomPrivateBytes = 19373,
}

impl PartialEq<u16> for Code {
    fn eq(&self, other: &u16) -> bool {
        *self as u16 == *other
    }
}

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

            if Code::EndOfOpt == code {
                options.push(end_of_opt());
                break;
            }

            let mut buf = vec![0; pad_to::<u32>(opt_len)];

            self.read_exact(&mut buf)?;

            buf.split_off(opt_len);

            options.push(match Code::from_u16(code) {
                Some(Code::CustomStr)
                | Some(Code::CustomBytes)
                | Some(Code::CustomPrivateStr)
                | Some(Code::CustomPrivateBytes) => {
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
    Opt::new(code, value)
}

pub fn end_of_opt<'a>() -> Opt<'a> {
    Opt::new(Code::EndOfOpt as u16, b"")
}

pub fn comment<'a>(value: &'a str) -> Opt<'a> {
    Opt::new(Code::Comment as u16, value)
}

pub fn custom_str<'a>(private_enterprise_number: u32, value: &'a str) -> Opt<'a> {
    Opt::custom(Code::CustomStr, private_enterprise_number, value)
}

pub fn custom_bytes<'a>(private_enterprise_number: u32, value: &'a [u8]) -> Opt<'a> {
    Opt::custom(Code::CustomBytes, private_enterprise_number, value)
}

pub fn custom_private_str<'a>(private_enterprise_number: u32, value: &'a str) -> Opt<'a> {
    Opt::custom(Code::CustomPrivateStr, private_enterprise_number, value)
}

pub fn custom_private_bytes<'a>(private_enterprise_number: u32, value: &'a [u8]) -> Opt<'a> {
    Opt::custom(Code::CustomPrivateBytes, private_enterprise_number, value)
}

impl<'a> Opt<'a> {
    pub fn new<T: AsRef<[u8]> + ?Sized>(code: u16, value: &'a T) -> Opt<'a> {
        let buf = value.as_ref();

        Opt {
            code,
            len: buf.len() as u16,
            pen: None,
            value: buf.into(),
        }
    }

    pub fn custom<T: AsRef<[u8]> + ?Sized>(
        code: Code,
        private_enterprise_number: u32,
        value: &'a T,
    ) -> Opt<'a> {
        let buf = value.as_ref();

        Opt {
            code: code as u16,
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

    pub fn code(&self) -> StdResult<Code, u16> {
        Code::from_u16(self.code).ok_or(self.code)
    }

    pub fn value(&self) -> &[u8] {
        if self.len as usize <= self.value.len() {
            &self.value[..self.len as usize]
        } else {
            &self.value
        }
    }

    pub fn is_end_of_opt(&self) -> bool {
        self.code == Code::EndOfOpt as u16
    }

    pub fn as_comment(&self) -> Option<&str> {
        if self.code() == Ok(Code::Comment) {
            str::from_utf8(self.value()).ok()
        } else {
            None
        }
    }

    pub fn as_custom_str(&self) -> Option<(u32, &str)> {
        if self.code() == Ok(Code::CustomStr) {
            str::from_utf8(self.value())
                .ok()
                .and_then(|s| self.pen.map(|pen| (pen, s)))
        } else {
            None
        }
    }

    pub fn as_custom_bytes(&self) -> Option<(u32, &[u8])> {
        if self.code() == Ok(Code::CustomBytes) {
            self.pen.map(|pen| (pen, self.value()))
        } else {
            None
        }
    }

    pub fn as_custom_private_str(&self) -> Option<(u32, &str)> {
        if self.code() == Ok(Code::CustomPrivateStr) {
            str::from_utf8(self.value())
                .ok()
                .and_then(|s| self.pen.map(|pen| (pen, s)))
        } else {
            None
        }
    }
    pub fn as_custom_private_bytes(&self) -> Option<(u32, &[u8])> {
        if self.code() == Ok(Code::CustomPrivateBytes) {
            self.pen.map(|pen| (pen, self.value()))
        } else {
            None
        }
    }
}

named_args!(parse_options(endianness: Endianness)<Options>,
    dbg_dmp!(map!(many_till!(apply!(parse_opt, endianness), tag!(b"\0\0\0\0")), |(mut options, _)| {
        options.push(end_of_opt());
        options
    }))
);

named_args!(parse_opt(endianness: Endianness)<Opt>,
    dbg_dmp!(do_parse!(
        code: u16!(endianness) >>
        opt_len: u16!(endianness) >>
        pen: switch!(map!(value!(code), Code::from_u16),
            Some(Code::CustomStr)           => map!(u32!(endianness), Some) |
            Some(Code::CustomBytes)         => map!(u32!(endianness), Some) |
            Some(Code::CustomPrivateStr)    => map!(u32!(endianness), Some) |
            Some(Code::CustomPrivateBytes)  => map!(u32!(endianness), Some) |
            _                               => value!(None)
        ) >>
        val_len: value!(opt_len as usize - pen.map_or(0, |_| mem::size_of::<u32>())) >>
        value: map!(map!(take!(pad_to::<u32>(val_len)), |s| &s[..val_len]), Cow::from) >>
        (
            Opt { code, len: opt_len as u16, pen, value }
        )
    ))
);

fn pad_to<T>(size: usize) -> usize {
    let pad_size = mem::size_of::<T>();

    ((size + pad_size - 1) / pad_size) * pad_size
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_option_size() {
        assert_eq!(end_of_opt().size(), 4);
        assert_eq!(comment("test").size(), 8);
        assert_eq!(comment("foo").size(), 8);
        assert_eq!(custom_str(123, "test").size(), 12);
        assert_eq!(custom_bytes(123, b"foo").size(), 12);
        assert_eq!(custom_private_str(123, "test").size(), 12);
        assert_eq!(custom_private_bytes(123, b"foo").size(), 12);
    }

    const LE_OPTIONS: &[u8] = b"\x01\x00\x0a\x00Windows XP\x00\x00\
    \xac\x0b\x0f\x00\x7b\x00\x00\x00Test004.exe\x00\
    \x05\x00\x03\x00foo\x00\
    \x00\x00\x00\x00";

    #[test]
    fn test_parse_options() {
        let mut input = &LE_OPTIONS[..];

        let options = input.read_options(Endianness::Little).unwrap();

        assert_eq!(
            options,
            vec![
                comment("Windows XP"),
                custom_str(123, "Test004.exe"),
                opt(5, "foo"),
                end_of_opt(),
            ]
        );
    }

    #[test]
    fn test_read_options() {
        let mut input = BufReader::new(&LE_OPTIONS[..]);

        let options = input.read_options(Endianness::Little).unwrap();

        assert_eq!(
            options,
            vec![
                comment("Windows XP"),
                custom_str(123, "Test004.exe"),
                opt(5, "foo"),
                end_of_opt(),
            ]
        );
    }
}
