use std::fs::File;
use std::io::{BufReader, Cursor, Read};
use std::marker::PhantomData;
use std::path::Path;

use memmap::Mmap;

use super::{FileHeader, Packet};
use errors::Result;

pub struct Reader<'a, T: 'a> {
    r: T,
    phantom: PhantomData<&'a T>,
}

impl<'a, T: 'a> Reader<'a, T> {
    pub fn new(r: T) -> Self {
        Reader {
            r,
            phantom: PhantomData,
        }
    }
}

pub fn read<'a, R: Read>(read: R) -> Result<Reader<'a, BufReader<R>>> {
    Ok(Reader::new(BufReader::new(read)))
}

pub fn open<'a, P: AsRef<Path>>(path: P) -> Result<Reader<'a, BufReader<File>>> {
    let f = File::open(path)?;

    Ok(Reader::new(BufReader::new(f)))
}

pub fn mmap<'a, P: AsRef<Path>>(path: P) -> Result<Reader<'a, Cursor<Mmap>>> {
    let f = File::open(path)?;
    let mmap = unsafe { Mmap::map(&f)? };

    Ok(Reader::new(Cursor::new(mmap)))
}

pub fn parse<'a, T: AsRef<[u8]>>(buf: T) -> Result<Reader<'a, Cursor<T>>> {
    Ok(Reader::new(Cursor::new(buf)))
}

impl<'a, T> IntoIterator for &'a Reader<'a, Cursor<T>>
where
    T: AsRef<[u8]>,
{
    type Item = <GetPackets<'a> as Iterator>::Item;
    type IntoIter = GetPackets<'a>;

    fn into_iter(self) -> Self::IntoIter {
        GetPackets::new(self.r.get_ref())
    }
}

pub type GetPackets<'a> = get::Packets<'a>;

mod get {
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
        Parsed(&'a [u8], Endianness),
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
                                State::Parsed(remaining, file_header.magic().endianness())
                            } else {
                                State::Finished
                            }
                    }
                    State::Parsed(mut remaining, endianness) => {
                        if let Ok(packet) = remaining.read_packet(endianness) {
                            self.state = State::Parsed(remaining, endianness);

                            return Some(packet);
                        }

                        self.state = State::Finished;
                    }
                    State::Finished => return None,
                }
            }
        }
    }
}

impl<'a, T> IntoIterator for Reader<'a, BufReader<T>>
where
    T: Read,
{
    type Item = <ReadPackets<'a, T> as Iterator>::Item;
    type IntoIter = ReadPackets<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        ReadPackets::new(self.r)
    }
}

pub type ReadPackets<'a, T> = read::Packets<'a, T>;

mod read {
    use std::cell::Cell;

    use nom::Endianness;

    use super::*;
    use pcap::ReadPacketExt;

    pub struct Packets<'a, T: 'a> {
        state: Cell<State<T>>,
        phantom: PhantomData<&'a T>,
    }

    impl<'a, T: 'a> Packets<'a, T> {
        pub fn new(reader: BufReader<T>) -> Self {
            Packets {
                state: Cell::new(State::Init(reader)),
                phantom: PhantomData,
            }
        }
    }

    enum State<T> {
        Init(BufReader<T>),
        Parsed(BufReader<T>, Endianness),
        Finished,
    }

    impl<T> Default for State<T> {
        fn default() -> Self {
            State::Finished
        }
    }

    impl<'a, T> Iterator for Packets<'a, T>
    where
        T: 'a + Read,
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
                                    State::Parsed(reader, file_header.magic().endianness())
                                })
                                .unwrap_or(State::Finished),
                        );
                    }
                    State::Parsed(mut reader, endianness) => {
                        if let Ok(packet) = reader.read_packet(endianness) {
                            self.state = Cell::new(State::Parsed(reader, endianness));

                            return Some(packet);
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
        for (buf, _) in PACKETS.iter() {
            let mut packets = read(*buf).unwrap().into_iter();

            let packet = packets.next().unwrap();

            assert_eq!(packet.header.ts_sec, 0x56506e1a);
            assert_eq!(packet.header.ts_usec, 0x182b0ad0);
            assert_eq!(packet.header.incl_len, 4);
            assert_eq!(packet.header.orig_len, 60);
            assert_eq!(packet.payload, Cow::from(&[0x44u8, 0x41, 0x54, 0x41][..]));

            assert!(packets.next().is_none());
        }
    }

    #[test]
    pub fn test_parse_packets() {
        for (buf, _) in PACKETS.iter() {
            let reader = parse(buf).unwrap();
            let mut packets = reader.into_iter();

            let packet = packets.next().unwrap();

            assert_eq!(packet.header.ts_sec, 0x56506e1a);
            assert_eq!(packet.header.ts_usec, 0x182b0ad0);
            assert_eq!(packet.header.incl_len, 4);
            assert_eq!(packet.header.orig_len, 60);
            assert_eq!(packet.payload, Cow::from(&[0x44u8, 0x41, 0x54, 0x41][..]));

            assert!(packets.next().is_none());
        }
    }
}
