#![feature(slice_patterns)]

extern crate goblin;
extern crate keystone;
#[macro_use]
extern crate lazy_static;
extern crate byteorder;
#[macro_use]
extern crate log;
extern crate failure;
extern crate regex;
#[macro_use]
extern crate failure_derive;
extern crate fxhash;
extern crate parking_lot;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;

#[cfg(test)]
extern crate env_logger;

pub mod byteorder_ext;
pub mod pattern;
pub mod pattern_database;

use std::error::Error;
use std::fs::File;
use std::path::Path;

use keystone::{Arch, AsmResult, Keystone};
use parking_lot::Mutex;
use pattern_database::PatternDatabase;

pub fn keystone_assemble(assembly: String) -> Result<AsmResult, keystone::Error> {
    lazy_static! {
        static ref KEYSTONE: Mutex<Keystone> = Mutex::new(
            Keystone::new(Arch::X86, keystone::MODE_64)
                .expect("Failed to initialize Keystone engine")
        );
    }
    KEYSTONE.lock().asm(assembly, 0)
}

pub fn load_pattern_database_from_json<P: AsRef<Path>>(
    path: P,
) -> Result<PatternDatabase, Box<Error>> {
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
        .parse("trace")
        .init();
}
