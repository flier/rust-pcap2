use std::fs::File;
use std::io::{BufReader, Cursor, Read};
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};

use memmap::Mmap;

use errors::Result;
use pcap::{FileHeader, Packet, RawPacket};

pub fn open<'a, P: AsRef<Path>>(path: P) -> Result<Reader<'a, BufReader<File>>> {
    let f = File::open(path)?;

    read(f)
}

pub fn read<'a, R: Read>(read: R) -> Result<Reader<'a, BufReader<R>>> {
    Ok(Reader::new(BufReader::new(read)))
}

pub fn mmap<'a, P: AsRef<Path>>(path: P) -> Result<Reader<'a, Cursor<Mmap>>> {
    let f = File::open(path)?;
    let mmap = unsafe { Mmap::map(&f)? };

    parse(mmap)
}

pub fn parse<'a, T: AsRef<[u8]>>(buf: T) -> Result<Reader<'a, Cursor<T>>> {
    Ok(Reader::new(Cursor::new(buf)))
}

pub struct Reader<'a, R: 'a> {
    r: R,
    phantom: PhantomData<&'a R>,
}

impl<'a, R: 'a> Reader<'a, R> {
    pub fn new(r: R) -> Self {
        Reader {
            r,
            phantom: PhantomData,
        }
    }
}

impl<'a, R> Deref for Reader<'a, R> {
    type Target = R;

    fn deref(&self) -> &Self::Target {
        &self.r
    }
}

impl<'a, R> DerefMut for Reader<'a, R> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.r
    }
}

impl<'a> From<(RawPacket<'a>, i32, bool)> for Packet<'a> {
    fn from(args: (RawPacket<'a>, i32, bool)) -> Self {
        let (raw_packet, utc_offset, is_nanosecond_resolution) = args;

        let secs = u64::from(raw_packet.ts_sec);
        let secs = if utc_offset < 0 {
            secs.checked_sub(utc_offset.abs() as u64)
        } else {
            secs.checked_add(utc_offset as u64)
        }.unwrap_or_default();

        let nanos = if is_nanosecond_resolution {
            raw_packet.ts_usec
        } else {
            raw_packet.ts_usec.checked_mul(1000).unwrap_or_default()
        };

        Packet {
            timestamp: UNIX_EPOCH + Duration::new(secs, nanos % 1_000_000_000),
            actual_length: raw_packet.orig_len as usize,
            payload: raw_packet.payload,
        }
    }
}

impl<'a, T> IntoIterator for &'a Reader<'a, Cursor<T>>
where
    T: AsRef<[u8]>,
{
    type Item = <ParsePackets<'a> as Iterator>::Item;
    type IntoIter = ParsePackets<'a>;

    fn into_iter(self) -> Self::IntoIter {
        ParsePackets::new(self.r.get_ref())
    }
}

pub type ParsePackets<'a> = parse::Packets<'a>;

mod parse {
    use nom::Endianness;

    use super::*;
    use pcap::ReadPacketExt;

    pub struct Packets<'a> {
        state: State<'a>,
    }

    impl<'a> Packets<'a> {
        pub fn new<T: AsRef<[u8]>>(buf: &'a T) -> Packets<'a> {
            Packets {
                state: State::Init(buf.as_ref()),
            }
        }
    }

    enum State<'a> {
        Init(&'a [u8]),
        Parsed(&'a [u8], Endianness, i32, bool),
        Finished,
    }

    impl<'a> Iterator for Packets<'a> {
        type Item = Packet<'a>;

        fn next(&mut self) -> Option<Self::Item> {
            loop {
                match self.state {
                    State::Init(remaining) => {
                        self.state =
                            if let Ok((remaining, file_header)) = FileHeader::parse(remaining) {
                                let magic = file_header.magic();

                                State::Parsed(
                                    remaining,
                                    magic.endianness(),
                                    file_header.thiszone,
                                    magic.is_nanosecond_resolution(),
                                )
                            } else {
                                State::Finished
                            }
                    }
                    State::Parsed(
                        mut remaining,
                        endianness,
                        utc_offset,
                        is_nanosecond_resolution,
                    ) => {
                        if let Ok(packet) = remaining.read_packet(endianness) {
                            self.state = State::Parsed(
                                remaining,
                                endianness,
                                utc_offset,
                                is_nanosecond_resolution,
                            );

                            return Some(Packet::from((
                                packet,
                                utc_offset,
                                is_nanosecond_resolution,
                            )));
                        }

                        self.state = State::Finished;
                    }
                    State::Finished => return None,
                }
            }
        }
    }
}

impl<'a, R> IntoIterator for Reader<'a, BufReader<R>>
where
    R: Read,
{
    type Item = <ReadPackets<'a, R> as Iterator>::Item;
    type IntoIter = ReadPackets<'a, R>;

    fn into_iter(self) -> Self::IntoIter {
        ReadPackets::new(self.r)
    }
}

pub type ReadPackets<'a, R> = read::Packets<'a, R>;

mod read {
    use std::cell::Cell;

    use nom::Endianness;

    use super::*;
    use pcap::ReadPacketExt;

    pub struct Packets<'a, R: 'a> {
        state: Cell<State<R>>,
        phantom: PhantomData<&'a R>,
    }

    impl<'a, R: 'a> Packets<'a, R> {
        pub fn new(reader: BufReader<R>) -> Self {
            Packets {
                state: Cell::new(State::Init(reader)),
                phantom: PhantomData,
            }
        }
    }

    enum State<R> {
        Init(BufReader<R>),
        Parsed(BufReader<R>, Endianness, i32, bool),
        Finished,
    }

    impl<R> Default for State<R> {
        fn default() -> Self {
            State::Finished
        }
    }

    impl<'a, R> Iterator for Packets<'a, R>
    where
        R: 'a + Read,
    {
        type Item = Packet<'a>;

        fn next(&mut self) -> Option<Self::Item> {
            loop {
                match self.state.take() {
                    State::Init(mut reader) => {
                        let mut buf = vec![0; FileHeader::size()];

                        self.state = Cell::new(
                            reader
                                .read_exact(&mut buf)
                                .map_err(|err| err.into())
                                .and_then(|_| FileHeader::parse(&buf))
                                .map(|(_, file_header)| {
                                    let magic = file_header.magic();

                                    State::Parsed(
                                        reader,
                                        magic.endianness(),
                                        file_header.thiszone,
                                        magic.is_nanosecond_resolution(),
                                    )
                                })
                                .unwrap_or(State::Finished),
                        );
                    }
                    State::Parsed(mut reader, endianness, utc_offset, is_nanosecond_resolution) => {
                        if let Ok(packet) = reader.read_packet(endianness) {
                            self.state = Cell::new(State::Parsed(
                                reader,
                                endianness,
                                utc_offset,
                                is_nanosecond_resolution,
                            ));

                            return Some(Packet::from((
                                packet,
                                utc_offset,
                                is_nanosecond_resolution,
                            )));
                        }
                    }
                    State::Finished => {
                        return None;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::borrow::Cow;

    use super::*;
    use pcap::tests::PACKETS;

    #[test]
    pub fn test_read_packets() {
        for (buf, magic) in PACKETS.iter() {
            let mut packets = read(*buf).unwrap().into_iter();

            let packet = packets.next().unwrap();
            let ts = packet.timestamp.duration_since(UNIX_EPOCH).unwrap();

            assert_eq!(ts.as_secs(), 0x56506e1a);
            assert_eq!(
                ts.subsec_nanos(),
                if magic.is_nanosecond_resolution() {
                    0x182b0ad0
                } else {
                    0
                }
            );

            assert_eq!(packet.actual_length, 60);
            assert_eq!(packet.payload, Cow::from(&[0x44u8, 0x41, 0x54, 0x41][..]));

            assert!(packets.next().is_none());
        }
    }

    #[test]
    pub fn test_parse_packets() {
        for (buf, magic) in PACKETS.iter() {
            let reader = parse(buf).unwrap();
            let mut packets = reader.into_iter();

            let packet = packets.next().unwrap();
            let ts = packet.timestamp.duration_since(UNIX_EPOCH).unwrap();

            assert_eq!(ts.as_secs(), 0x56506e1a);
            assert_eq!(
                ts.subsec_nanos(),
                if magic.is_nanosecond_resolution() {
                    0x182b0ad0
                } else {
                    0
                }
            );

            assert_eq!(packet.actual_length, 60);
            assert_eq!(packet.payload, Cow::from(&[0x44u8, 0x41, 0x54, 0x41][..]));

            assert!(packets.next().is_none());
        }
    }
}
