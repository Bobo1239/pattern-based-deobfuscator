use std::fmt::{self, Display};
use std::str::FromStr;

use fxhash::FxHashSet;
use keystone_assemble;
use regex::Regex;

#[derive(Debug, Fail, PartialEq)]
pub enum PatternError {
    #[fail(display = "invalid variable type: {}", _0)]
    InvalidVariableType(String),
    #[fail(display = "detection of the variable in the assembled pattern failed")]
    DetectionError,
    #[fail(display = "assembly of the pattern failed for all variable instantiations")]
    AssemblyFailed,
}

#[derive(Debug, PartialEq)]
pub struct Variable {
    name: String,
    typee: VariableType,
}

impl Variable {
    pub fn new(name: &str, typee: VariableType) -> Variable {
        Variable {
            name: name.to_string(),
            typee,
        }
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum VariableType {
    Number,
    Register,
}

#[derive(Debug, PartialEq)]
pub struct InstructionPattern {
    pattern: String,
    variables: Vec<Variable>,
}

impl InstructionPattern {
    pub fn pattern(&self) -> &str {
        &self.pattern
    }
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct Encoding(Vec<EncodingPart>);

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum EncodingPart {
    Fixed(Vec<u8>),
    Intermediate { length: u8, variable_name: String },
}

impl Encoding {
    // TODO: this will output regex groups with conflicting names
    pub fn to_regex(&self) -> String {
        let mut regex = String::new();
        for part in &self.0 {
            match part {
                EncodingPart::Fixed(bytes) => {
                    for byte in bytes {
                        regex += &format!(r"\x{:02x}", byte);
                    }
                }
                EncodingPart::Intermediate {
                    length,
                    variable_name,
                } => {
                    regex += &format!("(?P<{}>", variable_name);
                    for _ in 0..*length {
                        regex.push('.');
                    }
                    regex.push(')');
                }
            }
        }
        regex
    }
}

impl InstructionPattern {
    pub fn find_encodings(&self) -> Result<Vec<Encoding>, PatternError> {
        fn pattern_to_encodings(
            pattern: &InstructionPattern,
        ) -> Result<FxHashSet<Encoding>, PatternError> {
            fn detect_intermediate_len(encoded: &[u8]) -> Result<u8, PatternError> {
                match encoded {
                    [_.., 0x0F] => Ok(1),
                    [_.., 0x0F, _] => Ok(2),
                    [_.., 0x0F, _, _, _] => Ok(4),
                    [_.., 0x0F, _, _, _, _, _, _, _] => Ok(8),
                    _ => Err(PatternError::DetectionError),
                }
            }

            fn instantiate_and_detect_encoding(
                pattern: &InstructionPattern,
                instantiate_with: &str,
            ) -> Result<Encoding, PatternError> {
                let instance = pattern
                    .pattern
                    .replace(&pattern.variables[0].to_string(), instantiate_with);
                debug!("instance: {}", instance);
                match keystone_assemble(instance) {
                    Err(error) => {
                        warn!("assembly failed: {}", error);
                        Err(PatternError::AssemblyFailed)
                    }
                    Ok(encoded) => {
                        debug!("encoded:  {:x?}", encoded);
                        detect_intermediate_len(&encoded.bytes).map(|intermediate_len| {
                            let mut encoding = Vec::new();
                            encoding.push(EncodingPart::Fixed(
                                encoded.bytes
                                    [..(encoded.size - u32::from(intermediate_len)) as usize]
                                    .to_vec(),
                            ));
                            encoding.push(EncodingPart::Intermediate {
                                length: intermediate_len,
                                variable_name: pattern.variables[0].name.clone(),
                            });
                            Encoding(encoding)
                        })
                    }
                }
            }

            assert!(pattern.variables.len() == 1); //FIXME

            let mut encodings = FxHashSet::default();
            // TODO: we may have to check if 0x0F and 0xFF as some instruction have different encodings dependent on the sign
            let instantiations = ["0x0F", "0xDD0F", "0xDDDDDD0F", "0xDDDDDDDDDDDDDD0F"];
            let mut assembly_failed = true;
            for instantiation in &instantiations {
                let result = instantiate_and_detect_encoding(pattern, instantiation);
                if let Ok(encoding) = result {
                    encodings.insert(encoding);
                } else if Err(PatternError::AssemblyFailed) != result {
                    assembly_failed = false;
                }
            }

            if encodings.is_empty() {
                if assembly_failed {
                    Err(PatternError::AssemblyFailed)
                } else {
                    Err(PatternError::DetectionError)
                }
            } else {
                Ok(encodings)
            }
        }
        match self.variables.len() {
            0 => match keystone_assemble(self.pattern.to_string()).map(|asm| asm.bytes) {
                Ok(asm) => {
                    let mut parts = Vec::new();
                    parts.push(EncodingPart::Fixed(asm));
                    let mut encodings = Vec::new();
                    encodings.push(Encoding(parts));
                    Ok(encodings)
                }
                Err(_) => Err(PatternError::DetectionError),
            },
            1 => pattern_to_encodings(self).map(|set| set.into_iter().collect()),
            _ => unimplemented!(),
        }
    }
}

impl FromStr for InstructionPattern {
    type Err = PatternError;
    fn from_str(s: &str) -> Result<InstructionPattern, PatternError> {
        lazy_static! {
            static ref REGEX: Regex = Regex::new(r"\$(\w+):(\w+)").unwrap();
        }

        let mut vec = Vec::new();
        let captures_iter = REGEX.captures_iter(s);
        for captures in captures_iter {
            let type_str = &captures[1];
            let name = captures[2].to_string();
            let typee = match type_str {
                "num" => VariableType::Number,
                "reg" => VariableType::Register,
                typee => return Err(PatternError::InvalidVariableType(typee.to_string())),
            };
            let var = Variable { typee, name };
            if !vec.contains(&var) {
                vec.push(var);
            }
        }

        Ok(InstructionPattern {
            pattern: s.to_string(),
            variables: vec,
        })
    }
}

impl Display for Variable {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "${}:{}",
            match self.typee {
                VariableType::Number => "num",
                VariableType::Register => "reg",
            },
            self.name
        )
    }
}

// NOTE: This is only temporary
#[deprecated]
pub fn encodings_to_regex(encodings: &[Encoding]) -> String {
    let regexes: Vec<_> = encodings.iter().map(|enc| enc.to_regex()).collect();
    format!("({})", regexes.join("|"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_instruction_pattern() {
        use super::VariableType::*;
        fn test(pattern: &str, variables: Vec<Variable>) {
            assert_eq!(
                pattern.parse(),
                Ok(InstructionPattern {
                    pattern: pattern.to_string(),
                    variables: variables,
                })
            );
        }
        let var = Variable::new;

        test("move eax, ebx", vec![]);
        test(
            "move $reg:a, $reg:b",
            vec![var("a", Register), var("b", Register)],
        );
        test("move $reg:a, $reg:a", vec![var("a", Register)]);
        test("move eax, [$num:num1]", vec![var("num1", Number)]);
        test("move eax, [$num:42]", vec![var("42", Number)]);
        assert_eq!(
            "move $n:a, $r:b".parse::<InstructionPattern>(),
            Err(PatternError::InvalidVariableType("n".to_string()))
        );
    }
}
