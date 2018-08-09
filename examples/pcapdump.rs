#[macro_use]
extern crate log;
extern crate pretty_env_logger;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate structopt;
extern crate glob;
extern crate pnet;

use std::fmt;
use std::fs::File;
use std::io::{self, BufWriter, Read, Write};
use std::path::PathBuf;

use failure::Error;
use glob::glob;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(about = "dump pcap/pcapng file.")]
struct Opt {
    /// When parsing and printing, produce (slightly more) verbose output.
    #[structopt(short = "v")]
    verbose: bool,

    /// Read packets from file
    #[structopt(short = "r", parse(from_os_str))]
    files: Vec<PathBuf>,

    #[structopt(short = "o", parse(from_os_str))]
    output: Option<PathBuf>,
}

fn dump_files<W: Write>(w: &mut W, patterns: Vec<PathBuf>) -> Result<(), Error> {
    if patterns.is_empty() || patterns == vec![PathBuf::from("-")] {
        debug!("reading from stdin");

        let stdin = io::stdin();
        let mut handle = stdin.lock();

        dump_file(w, &mut handle)?;
    } else {
        for pattern in patterns {
            for entry in glob(pattern.to_str().unwrap()).expect("Failed to read glob pattern") {
                match entry {
                    Ok(path) => {
                        debug!("reading file {:?}", path);

                        let mut f = File::open(path)?;

                        dump_file(w, &mut f)?;
                    }
                    Err(err) => warn!("skip entry, {}", err),
                }
            }
        }
    }

    Ok(())
}

fn dump_file<W: Write, R: Read>(w: &mut W, r: &mut R) -> fmt::Result {
    Ok(())
}

fn main() {
    pretty_env_logger::init();

    let opt = Opt::from_args();

    debug!("parsed options: {:#?}", opt);

    match opt.output {
        Some(ref path) if *path != PathBuf::from("-") => {
            debug!("dump to file {:?}", path);

            let f = File::create(path).unwrap();
            let mut w = BufWriter::new(f);

            dump_files(&mut w, opt.files).expect("dump to file");
        }
        _ => {
            debug!("dump to stdout");

            let stdout = io::stdout();
            let mut handle = stdout.lock();
            let mut w = BufWriter::new(handle);

            dump_files(&mut w, opt.files).expect("dump to stdout");
        }
    }
}
