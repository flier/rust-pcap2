use std::borrow::Cow;
use std::mem;
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

pub fn parse_options<'a>(
    mut input: &'a [u8],
    endianness: Endianness,
) -> IResult<&'a [u8], Options<'a>> {
    let mut options = vec![];

    loop {
        let (remaining, opt) = parse_opt(input, endianness)?;

        let code = opt.code();

        options.push(opt);
        input = remaining;

        if code == Some(Code::EndOfOpt) || input.is_empty() {
            break;
        }
    }

    Ok((input, options))
}

#[derive(Clone, Debug)]
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

pub fn end_of_opt<'a>() -> Opt<'a> {
    Opt::new(Code::EndOfOpt, b"")
}

pub fn comment<'a>(value: &'a str) -> Opt<'a> {
    Opt::new(Code::Comment, value)
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
    pub fn new<T: AsRef<[u8]> + ?Sized>(code: Code, value: &'a T) -> Opt<'a> {
        let buf = value.as_ref();
        let len = pad_to::<u32>(buf.len() as usize);

        Opt {
            code: code as u16,
            len: len as u16,
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
        let len = pad_to::<u32>(buf.len() as usize);

        Opt {
            code: code as u16,
            len: len as u16,
            pen: Some(private_enterprise_number),
            value: buf.into(),
        }
    }

    pub fn size(&self) -> usize {
        mem::size_of::<u16>() * 2
            + self.pen.map_or(0, |n| mem::size_of_val(&n))
            + pad_to::<u32>(self.value.len())
    }

    pub fn parse(buf: &'a [u8], endianness: Endianness) -> Result<(&[u8], Self)> {
        parse_opt(buf, endianness).map_err(|err| PcapError::from(err).into())
    }

    pub fn code(&self) -> Option<Code> {
        Code::from_u16(self.code)
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
        if self.code() == Some(Code::Comment) {
            str::from_utf8(self.value()).ok()
        } else {
            None
        }
    }

    pub fn as_custom_str(&self) -> Option<(u32, &str)> {
        if self.code() == Some(Code::CustomStr) {
            str::from_utf8(self.value())
                .ok()
                .and_then(|s| self.pen.map(|pen| (pen, s)))
        } else {
            None
        }
    }

    pub fn as_custom_bytes(&self) -> Option<(u32, &[u8])> {
        if self.code() == Some(Code::CustomBytes) {
            self.pen.map(|pen| (pen, self.value()))
        } else {
            None
        }
    }

    pub fn as_custom_private_str(&self) -> Option<(u32, &str)> {
        if self.code() == Some(Code::CustomPrivateStr) {
            str::from_utf8(self.value())
                .ok()
                .and_then(|s| self.pen.map(|pen| (pen, s)))
        } else {
            None
        }
    }
    pub fn as_custom_private_bytes(&self) -> Option<(u32, &[u8])> {
        if self.code() == Some(Code::CustomPrivateBytes) {
            self.pen.map(|pen| (pen, self.value()))
        } else {
            None
        }
    }
}

named_args!(parse_opt(endianness: Endianness)<Opt>,
    do_parse!(
        code: u16!(endianness) >>
        len: u16!(endianness) >>
        pen: switch!(map_opt!(value!(code), Code::from_u16),
            Code::CustomStr             => map!(u32!(endianness), Some) |
            Code::CustomBytes           => map!(u32!(endianness), Some) |
            Code::CustomPrivateStr      => map!(u32!(endianness), Some) |
            Code::CustomPrivateBytes    => map!(u32!(endianness), Some) |
            _                           => value!(None)
        ) >>
        value: map!(take!(pad_to::<u32>(len as usize - pen.map_or(0, |n| mem::size_of_val(&n)))), Cow::from) >>
        (
            Opt { code, len, pen, value }
        )
    )
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
}
