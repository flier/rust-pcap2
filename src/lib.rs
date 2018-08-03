#[macro_use]
extern crate failure;
extern crate num_traits;
#[macro_use]
extern crate num_derive;
extern crate byteorder;
#[macro_use]
extern crate nom;
extern crate memmap;

#[cfg(test)]
#[macro_use]
extern crate lazy_static;
#[cfg(test)]
extern crate hexplay;

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
