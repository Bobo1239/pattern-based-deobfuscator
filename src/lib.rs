#![feature(slice_patterns, nll)]
#![warn(rust_2018_idioms)]

pub mod byteorder_ext;
pub mod pattern;
pub mod pattern_database;

use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io;
use std::path::Path;

use keystone::Error as KeystoneError;
use keystone::{Arch, AsmResult, Keystone, Mode};
use lazy_static::lazy_static;
use parking_lot::Mutex;

use pattern_database::PatternDatabase;

pub fn keystone_assemble(assembly: String) -> Result<AsmResult, KeystoneError> {
    lazy_static! {
        static ref KEYSTONE: Mutex<Keystone> = Mutex::new(
            Keystone::new(Arch::X86, Mode::MODE_64).expect("Failed to initialize Keystone engine")
        );
    }
    KEYSTONE.lock().asm(assembly, 0)
}

// Can't use keystone as it doesn't support NASM syntax: $ (refers to current assembly position)
pub fn nasm_assemble(asm: &str, _origin: u64) -> Result<Vec<u8>, io::Error> {
    // FIXME: ...
    // use std::io::{Read, Write};
    // use std::process::Command;
    // use tempfile::NamedTempFile;
    // let mut asm_file = NamedTempFile::new()?;
    // let mut result_file = NamedTempFile::new()?;

    // asm_file.write_all(b"BITS 64\n")?;
    // asm_file.write_all(b"SECTION .text\n")?;
    // asm_file.write_all(format!("ORG 0x{:x}\n", origin).as_bytes())?;
    // asm_file.write_all(asm.as_bytes())?;

    // if origin == 0x0000000140C693BC {
    //     println!("{}", asm);
    // } else {
    //     // warn!("{:x}", origin)
    // }

    // let result = Command::new("nasm")
    //     .arg(asm_file.path())
    //     .arg("-o")
    //     .arg(result_file.path())
    //     .status()?;

    // if result.success() {
    //     let mut vec = Vec::new();
    //     result_file.read_to_end(&mut vec)?;
    //     if origin == 0x0000000140C693BC {
    //         panic!("{:x?}", vec);
    //     }
    //     Ok(vec)
    // } else {
    //     Err(io::Error::new(io::ErrorKind::Other, NasmFailed))
    // }

    // FIXME: actually use nasm (need to create temp file as nasm doesn't have a library version?)
    keystone_assemble(asm.to_string())
        .map(|result| result.bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, NasmFailed))
}

#[derive(Debug)]
struct NasmFailed;
impl Error for NasmFailed {}
impl fmt::Display for NasmFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "nasm assembly failed")
    }
}

pub fn load_pattern_database_from_json<P: AsRef<Path>>(
    path: P,
) -> Result<PatternDatabase, Box<dyn Error>> {
    let file = File::open(path)?;
    let db = serde_json::from_reader(file)?;
    Ok(db)
}

#[cfg(test)]
#[allow(dead_code)]
fn init_logger() {
    env_logger::Builder::new()
        .target(env_logger::Target::Stdout)
        .default_format_timestamp(false)
        .parse_filters("trace")
        .init();
}
