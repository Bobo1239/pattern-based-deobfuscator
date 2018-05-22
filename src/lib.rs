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

#[cfg(test)]
extern crate env_logger;

pub mod byteorder_ext;
pub mod pattern;

use keystone::{Arch, Keystone};

lazy_static! {
    static ref KEYSTONE: Keystone =
        Keystone::new(Arch::X86, keystone::MODE_64).expect("Failed to initialize Keystone engine");
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
