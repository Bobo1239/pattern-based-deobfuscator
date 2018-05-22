extern crate byteorder;
extern crate keystone;
extern crate regex;
extern crate unhappy_arxan;
#[macro_use]
extern crate lazy_static;

use byteorder::LE;
use keystone::{Arch, Keystone};
use regex::bytes::Regex;
use unhappy_arxan::byteorder_ext::ByteOrderExt;
use unhappy_arxan::pattern::encodings_to_regex;
use unhappy_arxan::pattern::InstructionPattern;

lazy_static! {
    static ref KEYSTONE: Keystone = Keystone::new(Arch::X86, keystone::MODE_64).unwrap();
}

fn test(pattern: &str, should_match: Vec<(&str, u8, &[Vec<u8>])>) {
    let instruction_pattern: InstructionPattern = pattern.parse().unwrap();

    let regex = encodings_to_regex(&instruction_pattern.find_encodings().unwrap());
    println!("Regex: {}", regex);
    let regex = Regex::new(&(format!("^(?-u){}$", regex))).unwrap();

    for (instruction, expected_size, variables) in should_match {
        let assembled = KEYSTONE.asm(instruction.to_string(), 0).unwrap();
        assert_eq!(assembled.size as u8, expected_size);
        match regex.captures(&assembled.bytes) {
            Some(captures) => {
                for (i, var) in variables.iter().enumerate() {
                    assert_eq!(
                        captures.name(&format!("v{}", i + 1)).unwrap().as_bytes(),
                        &**var
                    )
                }
            }
            None => panic!("Didn't match pattern"),
        }
    }
}

// TODO: add test which try all different encoding (according to intel manual); lea, add, ...
#[test]
fn instruction_patterns_to_regex_one_operand() {
    test(
        "lea eax, [rip + $num:v1]",
        vec![
            ("lea eax, [rip + 0xFFEEDDCC]", 6, &[LE::u32_vec(0xFFEEDDCC)]),
            ("lea eax, [rip + 0x14]", 6, &[LE::i32_vec(0x14)]),
            ("lea eax, [rip - 0x14]", 6, &[LE::i32_vec(-0x14)]),
        ],
    );
    test(
        "lea rax, [rip + $num:v1]", // + REX.W prefix
        vec![
            ("lea rax, [rip + 0xFFEEDDCC]", 7, &[LE::u32_vec(0xFFEEDDCC)]),
            ("lea rax, [rip + 0x14]", 7, &[LE::i32_vec(0x14)]),
            ("lea rax, [rip - 0x14]", 7, &[LE::i32_vec(-0x14)]),
        ],
    );
}
