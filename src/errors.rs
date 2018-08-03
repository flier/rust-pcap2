use std::result::Result as StdResult;

pub use failure::Error;
use nom;

pub type Result<T> = StdResult<T, Error>;

/// The error type for this crate.
#[derive(Debug, Fail)]
pub enum PcapError {
    /// `Incomplete` indicates that more data is needed to decide.
    #[fail(display = "incomplete data, {:?}", _0)]
    IncompleteData(nom::Needed),

    /// `InvalidFormat` means some parser did not succeed
    #[fail(display = "invalid format, {:?}", _0)]
    InvalidFormat(nom::ErrorKind<u32>),
}

impl<I> From<nom::Err<I, u32>> for PcapError {
    fn from(err: nom::Err<I, u32>) -> Self {
        match err {
            nom::Err::Incomplete(needed) => PcapError::IncompleteData(needed),
            nom::Err::Error(ctx) | nom::Err::Failure(ctx) => {
                PcapError::InvalidFormat(ctx.into_error_kind())
            }
        }
    }
}
