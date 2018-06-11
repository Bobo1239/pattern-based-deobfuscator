extern crate byteorder;
extern crate env_logger;
extern crate quickcheck;
extern crate regex;
extern crate unhappy_arxan;

use std::ops::Deref;
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

fn quickcheck(tests: Vec<PatternTest>) {
    let mut qc = QuickCheck::new()
        .tests(QUICKCHECK_TESTS)
        .max_tests(QUICKCHECK_MAX_TESTS);

    for test in tests {
        qc.quickcheck(test);
    }
}

#[test]
fn quickcheck_one_number_var() {
    let pattern_tests = vec![
        PatternTest::new("lea eax, [rip + $num:n1]", vec![NumberWidth::Width64]),
        // PatternTest::new("lea eax, [rip - $num:v1]", vec![NumberWidth::Width64]),
        PatternTest::new("lea rax, [rip + $num:n1]", vec![NumberWidth::Width64]),
        // PatternTest::new("lea $reg:r1, [rip + $num:n1]", vec![NumberWidth::Width64]),
    ];
    quickcheck(pattern_tests);
}

#[test]
fn quickcheck_one_register_var() {
    let pattern_tests = vec![PatternTest::new("lea $reg:r1, [rip + 0x1000]", vec![])];
    quickcheck(pattern_tests);
}

struct PatternTest {
    pattern: InstructionPattern,
    regex: Regex,
    blacklisted_widths: Vec<NumberWidth>,
}

impl PatternTest {
    fn new(pattern: &str, blacklisted_widths: Vec<NumberWidth>) -> PatternTest {
        let pattern = InstructionPattern::from_str(pattern).unwrap();
        PatternTest {
            blacklisted_widths,
            regex: Regex::new(
                &(format!(
                    "^(?s-u){}$",
                    encodings_to_regex(&pattern.find_encodings().unwrap())
                )),
            ).unwrap(),
            pattern: pattern,
        }
    }
}

// TODO: blacklist register by width and individually

impl Testable for PatternTest {
    fn result<G: Gen>(&self, gen: &mut G) -> TestResult {
        let mut instance = self.pattern.pattern().to_owned();
        for reg in self.pattern.unique_register_variables() {
            instance = instance.replace(&reg.to_string(), RegisterWrapper::arbitrary(gen).name());
        }
        // FIXME: currently only supports one number variable
        let number = Number::arbitrary(gen);
        if self.blacklisted_widths.contains(&number.width()) {
            TestResult::discard()
        } else {
            let instance = instance.replace("$num:n1", &number.to_hex());
            println!("instance: {}", instance);
            if let Ok(assembled) = keystone_assemble(instance) {
                match self.regex.captures(&assembled.bytes) {
                    Some(captures) => {
                        // TODO: check matched register
                        match self.pattern.number_variables().count() {
                            0 => {}
                            1 => {
                                let matched_operand = captures.name("n1").unwrap().as_bytes();
                                let matched_operand = match matched_operand.len() {
                                    1 => matched_operand[0] as u64,
                                    2 => LE::read_u16(matched_operand) as u64,
                                    4 => LE::read_u32(matched_operand) as u64,
                                    8 => LE::read_u64(matched_operand) as u64,
                                    _ => unreachable!(),
                                };
                                assert_eq!(matched_operand, number.value());
                            }
                            _ => unimplemented!(),
                        }
                    }
                    None => panic!("Didn't match pattern"),
                }
                TestResult::passed()
            } else {
                TestResult::discard()
            }
        }
    }
}

#[derive(Debug, Clone)]
enum Number {
    Width8(u8),
    Width16(u16),
    Width32(u32),
    Width64(u64),
}

impl Number {
    fn value(&self) -> u64 {
        match *self {
            Number::Width8(op) => op as u64,
            Number::Width16(op) => op as u64,
            Number::Width32(op) => op as u64,
            Number::Width64(op) => op,
        }
    }

    fn to_hex(&self) -> String {
        format!("0x{:x}", self.value())
    }

    fn width(&self) -> NumberWidth {
        match self {
            Number::Width8(_) => NumberWidth::Width8,
            Number::Width16(_) => NumberWidth::Width16,
            Number::Width32(_) => NumberWidth::Width32,
            Number::Width64(_) => NumberWidth::Width64,
        }
    }
}

impl Arbitrary for Number {
    fn arbitrary<G: Gen>(gen: &mut G) -> Number {
        match gen.gen_range(0, 4) {
            0 => Number::Width8(gen.gen()),
            1 => Number::Width16(gen.gen()),
            2 => Number::Width32(gen.gen()),
            3 => Number::Width64(gen.gen()),
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, PartialEq)]
enum NumberWidth {
    Width8,
    Width16,
    Width32,
    Width64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RegisterWrapper(Register);

impl Arbitrary for RegisterWrapper {
    fn arbitrary<G: Gen>(gen: &mut G) -> RegisterWrapper {
        RegisterWrapper(*gen.choose(Register::all()).unwrap())
    }
}

impl Deref for RegisterWrapper {
    type Target = Register;

    fn deref(&self) -> &Register {
        &self.0
    }
}
