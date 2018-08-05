#[macro_use]
extern crate log;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate lazy_static;
extern crate num_traits;
#[macro_use]
extern crate num_derive;
extern crate byteorder;
#[macro_use]
extern crate nom;
extern crate hexplay;
extern crate memmap;

#[cfg(test)]
extern crate pretty_env_logger;

#[macro_use]
mod errors;
/// Supports the legacy `pcap` format.
///
/// See [Libpcap File Format](https://wiki.wireshark.org/Development/LibpcapFileFormat) for more details.
pub mod pcap;
/// Support the newer `pcapng` file format.
///
/// See [PCAP Next Generation Dump File Format](https://wiki.wireshark.org/Development/PcapNg) for more details.
pub mod pcapng;

pub use errors::PcapError;
