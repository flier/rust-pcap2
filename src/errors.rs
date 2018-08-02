use std::result::Result as StdResult;

pub use failure::Error;
use nom;

pub type Result<T> = StdResult<T, Error>;

#[derive(Debug, Fail)]
pub enum PcapError {
    #[fail(display = "unknown magic number: {}", _0)]
    UnknownMagic(u32),

    #[fail(display = "incomplete data, {:?}", _0)]
    Incomplete(nom::Needed),

    #[fail(display = "invalid format, {:?}", _0)]
    InvalidFormat(nom::ErrorKind<u32>),
}

impl<I> From<nom::Err<I, u32>> for PcapError {
    fn from(err: nom::Err<I, u32>) -> Self {
        match err {
            nom::Err::Incomplete(needed) => PcapError::Incomplete(needed),
            nom::Err::Error(ctx) | nom::Err::Failure(ctx) => {
                PcapError::InvalidFormat(ctx.into_error_kind())
            }
        }
    }
}
