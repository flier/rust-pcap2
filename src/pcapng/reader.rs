use std::fs::File;
use std::io::{BufReader, Cursor, Read, Seek};
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use std::path::Path;

use memmap::Mmap;

use errors::Result;
use pcapng::{Block, Packet};

/// Open a file as a stream in read-only mode.
pub fn open<'a, P: AsRef<Path>>(path: P) -> Result<Reader<'a, BufReader<File>>> {
    let f = File::open(path)?;

    read(f)
}

/// Read a stream implements `Read` trait in read-only mode.
pub fn read<'a, R: Read>(read: R) -> Result<Reader<'a, BufReader<R>>> {
    Ok(Reader::new(BufReader::new(read)))
}

/// Open a file as immutable memory mapped buffer in read-only mode.
pub fn mmap<'a, P: AsRef<Path>>(path: P) -> Result<Reader<'a, Cursor<Mmap>>> {
    let f = File::open(path)?;
    let mmap = unsafe { Mmap::map(&f)? };

    parse(mmap)
}

/// Parse a buffer implements `AsRef<[u8]>` trait in read-only mode.
pub fn parse<'a, T: AsRef<[u8]>>(buf: T) -> Result<Reader<'a, Cursor<T>>> {
    Ok(Reader::new(Cursor::new(buf)))
}

/// The `Reader` struct allows reading packets from a packet capture.
pub struct Reader<'a, R: 'a> {
    r: R,
    phantom: PhantomData<&'a R>,
}

impl<'a, R: 'a> Reader<'a, R> {
    /// Create a new `Reader` that reads the packet capture data from the specified `Reader`.
    pub fn new(r: R) -> Self {
        Reader {
            r,
            phantom: PhantomData,
        }
    }
}

impl<'a, T> Reader<'a, Cursor<T>>
where
    T: AsRef<[u8]>,
{
    pub fn blocks(&'a self) -> ParseBlocks<'a> {
        ParseBlocks::new(self.r.get_ref())
    }

    pub fn sections(&'a self) -> Sections<'a, ParseBlocks<'a>> {
        Sections { r: self.blocks() }
    }
}

impl<'a, R> Reader<'a, BufReader<R>>
where
    R: Read + Seek,
{
    pub fn blocks(self) -> ReadBlocks<'a, R> {
        ReadBlocks::new(self.r)
    }

    pub fn sections(self) -> Sections<'a, ReadBlocks<'a, R>> {
        Sections { r: self.blocks() }
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

impl<'a, R> IntoIterator for Reader<'a, R> {
    type Item = <Packets<'a, R> as Iterator>::Item;
    type IntoIter = Packets<'a, R>;

    fn into_iter(self) -> Self::IntoIter {
        Packets { r: self }
    }
}

pub type ParseBlocks<'a> = parse::Blocks<'a>;

mod parse {
    use std::io::Cursor;

    use nom::Endianness;

    use pcapng::block::ReadFileHeader;
    use pcapng::Block;

    pub struct Blocks<'a> {
        state: State<'a>,
    }

    impl<'a> Blocks<'a> {
        pub fn new<T: AsRef<[u8]>>(buf: &'a T) -> Blocks<'a> {
            Blocks {
                state: State::Init(buf.as_ref()),
            }
        }
    }

    impl<'a> Iterator for Blocks<'a> {
        type Item = Block<'a>;

        fn next(&mut self) -> Option<Self::Item> {
            loop {
                match self.state {
                    State::Init(remaining) => {
                        match Cursor::new(remaining).read_file_header() {
                            Ok(endianess) => {
                                self.state = State::Parsing(remaining, endianess);

                                continue;
                            }
                            Err(err) => debug!("skip pcap file, {:?}", err),
                        }

                        self.state = State::Done
                    }
                    State::Parsing(remaining, endianness) => {
                        match Block::parse(remaining, endianness) {
                            Ok((remaining, block)) => {
                                self.state = if remaining.is_empty() {
                                    State::Done
                                } else {
                                    State::Parsing(remaining, endianness)
                                };

                                trace!(
                                    "parsed {} block with {} bytes body\n{}",
                                    block.block_type().map_or_else(
                                        || format!("0x{:x}", block.ty),
                                        |block_type| format!("{:?}", block_type)
                                    ),
                                    block.body.len(),
                                    hexdump!(block.body)
                                );

                                return Some(block);
                            }
                            Err(err) => {
                                debug!("fail to parse file, {:?}", err);

                                self.state = State::Done
                            }
                        }
                    }
                    State::Done => break,
                }
            }

            None
        }
    }

    enum State<'a> {
        Init(&'a [u8]),
        Parsing(&'a [u8], Endianness),
        Done,
    }

}

pub type ReadBlocks<'a, R> = read::Blocks<'a, R>;

mod read {
    use std::cell::Cell;
    use std::io::{Error as IoError, ErrorKind as IoErrorKind};

    use byteorder::{BigEndian, LittleEndian};
    use nom::Endianness;

    use super::*;
    use pcapng::block::{ReadBlock, ReadFileHeader};

    pub struct Blocks<'a, R: 'a> {
        state: Cell<State<R>>,
        phantom: PhantomData<&'a R>,
    }

    enum State<R> {
        Init(BufReader<R>),
        Parsing(BufReader<R>, Endianness),
        Done,
    }

    impl<R> Default for State<R> {
        fn default() -> Self {
            State::Done
        }
    }

    impl<'a, R: 'a> Blocks<'a, R> {
        pub fn new(reader: BufReader<R>) -> Self {
            Blocks {
                state: Cell::new(State::Init(reader)),
                phantom: PhantomData,
            }
        }
    }

    impl<'a, R> Iterator for Blocks<'a, R>
    where
        R: Read + Seek,
    {
        type Item = Block<'a>;

        fn next(&mut self) -> Option<Self::Item> {
            loop {
                match self.state.take() {
                    State::Init(mut reader) => match reader.read_file_header() {
                        Ok(endianess) => {
                            self.state = Cell::new(State::Parsing(reader, endianess));

                            continue;
                        }
                        Err(err) => debug!("skip pcap file, {:?}", err),
                    },
                    State::Parsing(mut reader, endianness) => {
                        let result = match endianness {
                            Endianness::Little => reader.read_block::<LittleEndian>(),
                            Endianness::Big => reader.read_block::<BigEndian>(),
                        };

                        match result {
                            Ok(block) => {
                                trace!(
                                    "read {} block with {} bytes body\n{}",
                                    block.block_type().map_or_else(
                                        || format!("0x{:x}", block.ty),
                                        |block_type| format!("{:?}", block_type)
                                    ),
                                    block.body.len(),
                                    hexdump!(block.body)
                                );

                                self.state = Cell::new(State::Parsing(reader, endianness));

                                return Some(block);
                            }
                            Err(err) => {
                                if let Some(io_err) = err.downcast_ref::<IoError>() {
                                    if io_err.kind() == IoErrorKind::UnexpectedEof {
                                        break;
                                    }
                                }

                                debug!("fail to parse file, {}", err);
                            }
                        }
                    }
                    State::Done => break,
                }
            }

            None
        }
    }
}

pub struct Sections<'a, R>
where
    R: IntoIterator<Item = Block<'a>>,
{
    r: R,
}

pub struct Packets<'a, R: 'a> {
    r: Reader<'a, R>,
}

impl<'a, R> Iterator for Packets<'a, R> {
    type Item = Packet<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        None
    }
}

#[cfg(test)]
mod tests {
    use pretty_env_logger;

    use super::*;

    use pcapng::blocks::{
        enhanced_packet::tests::LE_ENHANCED_PACKET,
        interface_description::tests::LE_INTERFACE_DESCRIPTION,
        interface_statistics::tests::LE_INTERFACE_STATISTICS,
        name_resolution::tests::LE_NAME_RESOLUTION, obsoleted_packet::tests::LE_OBSOLETED_PACKET,
        section_header::tests::LE_SECTION_HEADER, simple_packet::tests::LE_SIMPLE_PACKET,
        BlockType,
    };

    lazy_static! {
        static ref LE_FILE: Vec<u8> = {
            let mut v = vec![];

            v.append(&mut LE_SECTION_HEADER.to_vec());
            v.append(&mut LE_INTERFACE_DESCRIPTION.to_vec());
            v.append(&mut LE_NAME_RESOLUTION.to_vec());
            v.append(&mut LE_ENHANCED_PACKET.to_vec());
            v.append(&mut LE_SIMPLE_PACKET.to_vec());
            v.append(&mut LE_OBSOLETED_PACKET.to_vec());
            v.append(&mut LE_INTERFACE_STATISTICS.to_vec());

            v
        };
    }

    #[test]
    fn test_parse_blocks() {
        let _ = pretty_env_logger::try_init();

        let reader = parse(LE_FILE.as_slice()).unwrap();

        assert_eq!(
            reader
                .blocks()
                .flat_map(|block| block.block_type())
                .collect::<Vec<_>>(),
            vec![
                BlockType::SectionHeader,
                BlockType::InterfaceDescription,
                BlockType::NameResolution,
                BlockType::EnhancedPacket,
                BlockType::SimplePacket,
                BlockType::ObsoletedPacket,
                BlockType::InterfaceStatistics,
            ]
        );
    }

    #[test]
    fn test_read_blocks() {
        let _ = pretty_env_logger::try_init();

        let reader = read(Cursor::new(LE_FILE.as_slice())).unwrap();

        assert_eq!(
            reader
                .blocks()
                .flat_map(|block| block.block_type())
                .collect::<Vec<_>>(),
            vec![
                BlockType::SectionHeader,
                BlockType::InterfaceDescription,
                BlockType::NameResolution,
                BlockType::EnhancedPacket,
                BlockType::SimplePacket,
                BlockType::ObsoletedPacket,
                BlockType::InterfaceStatistics,
            ]
        );
    }
}
