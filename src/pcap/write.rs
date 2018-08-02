use std::fs::File;
use std::io::Write;
use std::path::Path;

use errors::Result;

pub struct Writer<W> {
    w: W,
}

pub fn create<P: AsRef<Path>>(path: P) -> Result<Writer<File>> {
    Writer::new(File::create(path)?)
}

impl<W> Writer<W>
where
    W: Write,
{
    pub fn new(w: W) -> Result<Self> {
        Ok(Writer { w })
    }
}
