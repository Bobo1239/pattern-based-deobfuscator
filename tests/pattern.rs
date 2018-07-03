extern crate byteorder;
extern crate env_logger;
#[macro_use]
extern crate log;
extern crate quickcheck;
extern crate regex;
extern crate unhappy_arxan;

use std::ops::Deref;
use std::str::FromStr;

use quickcheck::{Arbitrary, Gen, QuickCheck, TestResult, Testable};

use unhappy_arxan::keystone_assemble;
use unhappy_arxan::pattern::*;

#[cfg(debug_assertions)]
const QUICKCHECK_TESTS: u64 = 1_000;
#[cfg(not(debug_assertions))]
const QUICKCHECK_TESTS: u64 = 10_000;
const QUICKCHECK_MAX_TESTS: u64 = 10 * QUICKCHECK_TESTS;

fn quickcheck(tests: Vec<PatternTest>) {
    let mut qc = QuickCheck::new()
        .tests(QUICKCHECK_TESTS)
        .max_tests(QUICKCHECK_MAX_TESTS);

    for test in tests {
        qc.quickcheck(test);
    }
}

// TODO: add test with instruction which has many different encodings (according to intel manual); lea, add, ...
#[test]
fn quickcheck_tests() {
    env_logger::init();
    let pattern_tests = vec![
        PatternTest::new("lea eax, [rip + $num:n1]", vec![NumberWidth::Width64]),
        PatternTest::new("lea rax, [rip + $num:n1]", vec![NumberWidth::Width64]),
        PatternTest::new("lea $reg:r1, [rip]", vec![NumberWidth::Width64]),
        PatternTest::new("lea $reg:r1, [rip + $num:n1]", vec![NumberWidth::Width64]),
        PatternTest::new(
            "lea $reg:r1, [$reg:r2 + $num:n1]",
            vec![NumberWidth::Width64],
        ),
        PatternTest::new(
            "lea $reg:r1, [$reg:r1 + $num:n1]",
            vec![NumberWidth::Width64],
        ),
    ];
    quickcheck(pattern_tests);
}

struct PatternTest {
    matcher: InstructionPatternMatcher,
    blacklisted_widths: Vec<NumberWidth>,
}

impl PatternTest {
    fn new(pattern: &str, blacklisted_widths: Vec<NumberWidth>) -> PatternTest {
        let pattern = InstructionPattern::from_str(pattern).unwrap();
        let matcher = InstructionPatternMatcher::new(pattern).unwrap();
        PatternTest {
            blacklisted_widths,
            matcher,
        }
    }
}

// TODO: blacklist register by width and individually

impl Testable for PatternTest {
    fn result<G: Gen>(&self, gen: &mut G) -> TestResult {
        let mut instance = self.matcher.pattern().pattern().to_owned();

        let variable_instantiations = {
            let mut vec = Vec::new();
            for variable in self.matcher.pattern().variables() {
                if vec.iter().any(|v: &InstantiatedVariable| {
                    v.name() == variable.name() && v.typee() == variable.typee()
                }) {
                    // Variable is already instantiated
                    continue;
                }

                match variable.typee() {
                    VariableType::Number => {
                        let mut number = Number::arbitrary(gen);
                        while self.blacklisted_widths.contains(&number.width()) {
                            number = Number::arbitrary(gen);
                        }
                        instance = instance
                            .replace(&format!("$num:{}", variable.name()), &number.to_hex());
                        vec.push(InstantiatedVariable::new_number(
                            variable.name().to_string(),
                            number.value(),
                        ));
                    }
                    VariableType::Register => {
                        let mut register = RegisterWrapper::arbitrary(gen);
                        instance =
                            instance.replace(&format!("$reg:{}", variable.name()), register.name());
                        vec.push(InstantiatedVariable::new_register(
                            variable.name().to_string(),
                            *register,
                        ));
                    }
                }
            }
            vec
        };
        debug!("test instance: {}", instance);

        if let Ok(assembled) = keystone_assemble(instance) {
            match self.matcher.match_against(&assembled.bytes) {
                Some((found_variables, matched_bytes)) => {
                    assert!(u32::from(matched_bytes) == assembled.size);
                    debug!("expected variables: {:x?}", variable_instantiations);
                    debug!("found variables: {:x?}", found_variables);
                    for variable_instantiation in variable_instantiations {
                        assert!(
                            found_variables.contains(&variable_instantiation),
                            "failed to find instantiated variable: {:x?}",
                            variable_instantiation
                        );
                    }
                }
                None => panic!("Didn't match pattern!"),
            }
            TestResult::passed()
        } else {
            TestResult::discard()
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
            Number::Width8(op) => u64::from(op),
            Number::Width16(op) => u64::from(op),
            Number::Width32(op) => u64::from(op),
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
        loop {
            let generated = match gen.gen_range(0, 4) {
                0 => Number::Width8(gen.gen()),
                1 => Number::Width16(gen.gen()),
                2 => Number::Width32(gen.gen()),
                3 => Number::Width64(gen.gen()),
                _ => unreachable!(),
            };
            // TODO: ideally, this wouldn't be necessary; but the encoding detection algorithm has
            //       to account for this and it doesn't really seem that useful in practice
            if generated.value() != 0 {
                return generated;
            }
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
