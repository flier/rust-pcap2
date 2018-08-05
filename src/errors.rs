use std::collections::HashMap;
use std::fmt::Write;
use std::result::Result as StdResult;

use failure::Error;
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

impl<'a> From<nom::Err<&'a [u8], u32>> for PcapError {
    fn from(err: nom::Err<&[u8], u32>) -> Self {
        warn!("parse failed: {:#?}", err);

        match err {
            nom::Err::Incomplete(needed) => PcapError::IncompleteData(needed),
            nom::Err::Error(ctx) | nom::Err::Failure(ctx) => {
                PcapError::InvalidFormat(ctx.into_error_kind())
            }
        }
    }
}

lazy_static! {
    static ref TAGS: HashMap<u32, &'static str> = {
        let mut tags: HashMap<u32, &str> = HashMap::new();
        tags.insert(0, "tag");
        tags
    };
}

#[allow(dead_code)]
pub fn format_nom_error<O>(input: &[u8], res: nom::IResult<&[u8], O>) -> String {
    let mut output = String::new();

    if let Some(v) = nom::prepare_errors(input, res) {
        let colors = nom::generate_colors(&v);
        write!(&mut output, "parsers: {}", nom::print_codes(&colors, &TAGS)).unwrap();
        write!(&mut output, "{}", nom::print_offsets(input, 0, &v)).unwrap();
    }

    output
}

#[macro_export]
macro_rules! hexdump {
    ($data:expr) => {
        hexdump!($data, 0)
    };
    ($data:expr, $offset:expr) => {
        hexdump!($data, $offset, 16)
    };
    ($data:expr, $offset:expr, $width:expr) => {
        ::hexplay::HexViewBuilder::new(&$data)
            .address_offset($offset)
            .row_width($width)
            .finish()
    };
}
