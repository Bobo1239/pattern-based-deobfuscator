extern crate byteorder;
extern crate quickcheck;
extern crate regex;
extern crate unhappy_arxan;

use std::str::FromStr;

use byteorder::{ByteOrder, LE};
use quickcheck::{Arbitrary, Gen, QuickCheck, TestResult, Testable};
use regex::bytes::Regex;

use unhappy_arxan::byteorder_ext::ByteOrderExt;
use unhappy_arxan::keystone_assemble;
use unhappy_arxan::pattern::*;

const QUICKCHECK_TESTS: u64 = 10_000;
const QUICKCHECK_MAX_TESTS: u64 = 10 * QUICKCHECK_TESTS;

fn test(pattern: &str, should_match: Vec<(&str, u8, &[Vec<u8>])>) {
    let instruction_pattern: InstructionPattern = pattern.parse().unwrap();

    let regex = encodings_to_regex(&instruction_pattern.find_encodings().unwrap());
    println!("Regex: {}", regex);
    let regex = Regex::new(&(format!("^(?s-u){}$", regex))).unwrap();

    for (instruction, expected_size, variables) in should_match {
        let assembled = keystone_assemble(instruction.to_string()).unwrap();
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
            None => panic!("Didn't match regex: {:x?}", assembled.bytes),
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
            ("lea eax, [rip + 0x6a0a]", 6, &[LE::i32_vec(0x6a0a)]),
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

#[test]
fn quickcheck() {
    let pattern_tests = vec![
        ("lea eax, [rip + $num:v1]", vec![OperandWidth::Width64]),
        // ("lea eax, [rip - $num:v1]", vec![OperandWidth::Width64]),
        ("lea rax, [rip + $num:v1]", vec![OperandWidth::Width64]),
    ].into_iter()
        .map(|(pat, blacklisted)| PatternTest {
            pattern: pat,
            regex: Regex::new(
                &(format!(
                    "^(?s-u){}$",
                    encodings_to_regex(
                        &InstructionPattern::from_str(pat)
                            .unwrap()
                            .find_encodings()
                            .unwrap()
                    )
                )),
            ).unwrap(),
            blacklisted_widths: blacklisted,
        });
    let mut qc = QuickCheck::new()
        .tests(QUICKCHECK_TESTS)
        .max_tests(QUICKCHECK_MAX_TESTS);
    for test in pattern_tests {
        qc.quickcheck(test);
    }
}

struct PatternTest {
    pattern: &'static str,
    regex: Regex,
    blacklisted_widths: Vec<OperandWidth>,
}

impl Testable for PatternTest {
    fn result<G: Gen>(&self, gen: &mut G) -> TestResult {
        let operand = Operand::arbitrary(gen);
        if self.blacklisted_widths.contains(&operand.width()) {
            return TestResult::discard();
        }

        let instance = self.pattern.replace("$num:v1", &operand.to_hex());
        println!("instance: {}", instance);
        let assembled = keystone_assemble(instance).unwrap();
        match self.regex.captures(&assembled.bytes) {
            Some(captures) => {
                let matched_operand = captures.name("v1").unwrap().as_bytes();
                let matched_operand = match matched_operand.len() {
                    1 => matched_operand[0] as u64,
                    2 => LE::read_u16(matched_operand) as u64,
                    4 => LE::read_u32(matched_operand) as u64,
                    8 => LE::read_u64(matched_operand) as u64,
                    _ => unreachable!(),
                };
                assert_eq!(matched_operand, operand.value())
            }
            None => panic!("Didn't match pattern"),
        }
        TestResult::passed()
    }
}

#[derive(Debug, Clone)]
enum Operand {
    Width8(u8),
    Width16(u16),
    Width32(u32),
    Width64(u64),
}

impl Operand {
    fn value(&self) -> u64 {
        match *self {
            Operand::Width8(op) => op as u64,
            Operand::Width16(op) => op as u64,
            Operand::Width32(op) => op as u64,
            Operand::Width64(op) => op,
        }
    }

    fn to_hex(&self) -> String {
        format!("0x{:x}", self.value())
    }

    fn width(&self) -> OperandWidth {
        match self {
            Operand::Width8(_) => OperandWidth::Width8,
            Operand::Width16(_) => OperandWidth::Width16,
            Operand::Width32(_) => OperandWidth::Width32,
            Operand::Width64(_) => OperandWidth::Width64,
        }
    }
}

impl Arbitrary for Operand {
    fn arbitrary<G: Gen>(gen: &mut G) -> Operand {
        match gen.gen_range(0, 4) {
            0 => Operand::Width8(gen.gen()),
            1 => Operand::Width16(gen.gen()),
            2 => Operand::Width32(gen.gen()),
            3 => Operand::Width64(gen.gen()),
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, PartialEq)]
enum OperandWidth {
    Width8,
    Width16,
    Width32,
    Width64,
}
