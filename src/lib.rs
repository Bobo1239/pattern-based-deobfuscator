#![feature(never_type, slice_patterns)]

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
extern crate fnv;

#[cfg(test)]
extern crate env_logger;

mod byteorder_ext;
pub mod pattern;

#[cfg(test)]
#[allow(dead_code)]
fn init_logger() {
    env_logger::Builder::new()
        .target(env_logger::Target::Stdout)
        .default_format_timestamp(false)
        .parse("trace")
        .init();
}
