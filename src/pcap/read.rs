use std::fs::File;
use std::io::{BufReader, Cursor, Read};
use std::marker::PhantomData;
use std::path::Path;

use memmap::Mmap;
use nom::Needed;

use super::{FileHeader, Packet, ReadPacketExt};
use errors::{PcapError, Result};

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

pub fn open<'a, P: AsRef<Path>, T>(path: P) -> Result<Reader<'a, BufReader<File>>> {
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
        GetPackets {
            file_header: None,
            remaining: self.r.get_ref().as_ref(),
        }
    }
}

pub struct GetPackets<'a> {
    file_header: Option<FileHeader>,
    remaining: &'a [u8],
}

impl<'a> Iterator for GetPackets<'a> {
    type Item = Packet<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.file_header.is_none() {
            if let Ok((remaining, file_header)) = FileHeader::parse(self.remaining) {
                self.file_header = Some(file_header);
                self.remaining = remaining;
            }
        }

        if let Some(ref file_header) = self.file_header {
            self.remaining
                .read_packet(file_header.magic().endianness())
                .ok()
        } else {
            None
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
        ReadPackets {
            r: self.r,
            file_header: None,
            phantom: PhantomData,
        }
    }
}

pub struct ReadPackets<'a, T>
where
    T: 'a + Read,
{
    r: BufReader<T>,
    file_header: Option<FileHeader>,
    phantom: PhantomData<&'a T>,
}

impl<'a, T> ReadPackets<'a, T>
where
    T: 'a + Read,
{
    fn read_packet(&mut self) -> Result<Packet<'a>> {
        if self.file_header.is_none() {
            let mut buf = vec![0; FileHeader::size()];

            self.r.read_exact(&mut buf)?;
            let (_, file_header) = FileHeader::parse(&buf)?;

            self.file_header = Some(file_header);
        }

        let file_header = self.file_header
            .as_ref()
            .ok_or_else(|| PcapError::Incomplete(Needed::Unknown))?;

        self.r.read_packet(file_header.magic().endianness())
    }
}

impl<'a, T> Iterator for ReadPackets<'a, T>
where
    T: 'a + Read,
{
    type Item = Packet<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.read_packet().ok()
    }
}

#[cfg(test)]
mod test {
    use super::*;
}
