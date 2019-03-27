# PBD: Pattern-Based Deobfuscator

[![Build Status](https://dev.azure.com/bobo1239/Pattern-Based%20Deobfuscator/_apis/build/status/Bobo1239.pattern-based-deobfuscator?branchName=master)](https://dev.azure.com/bobo1239/Pattern-Based%20Deobfuscator/_build/latest?definitionId=1&branchName=master)

TODO: Description

## Compilation

Compilation currently requires a nightly Rust compiler. (This will change in the future.) The
easiest way to install Rust is via [Rustup](https://rustup.rs/).

Starting `pbd` is then simply a matter of running `cargo run -- input.exe`. The `--` denotes that
further arguments are passed to `pbd` instead of `cargo`.

## Installation

If a more permanent install is desired, you can run `cargo install` which installs `pbd` to Cargo's
install directory (which should be in your `$PATH`).

## Pattern Definition Language

Patterns to be search for are defined in a json file. This defaults to `pattern_database.json`.
Each entry contains the pattern and the corresponding replacement which are both just lists of
assembly instructions. These instructions may use three types of variables:

- `$len:name` which must be at the start of the instruction and refers to the length of the current
  instruction in bytes
- `$num:name` which refers to any number
- `$reg:name` which refers to any general-purpose register (currently: rbx, rcx, rdx, rbp, rsp, rsi,
  rdi and the corresponding 32-bit variants)

## Current Limitations

- Only `x86_64` is supported.
- Only one number variable per instruction is allowed.
- Multi-pass is not implemented yet.

These are some limitations which can be removed without too much work:

- Only Windows PE executables can be used as input.

## TODO
- Consider stuff from [this talk](https://www.youtube.com/watch?v=eunYrrcxXfw)

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
