mod matcher;

use std::fmt::{self, Display};
use std::hash::Hash;
use std::str::FromStr;

use failure::Fail;
use fxhash::FxHashSet;
use lazy_static::lazy_static;
use log::*;
use regex::Regex;
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_derive::{Deserialize, Serialize};

pub use self::matcher::*;
use crate::keystone_assemble;

#[derive(Debug, Fail, PartialEq, Eq, Hash)]
pub enum PatternError {
    #[fail(display = "invalid variable type: {}", _0)]
    InvalidVariableType(String),
    #[fail(display = "detection of the variable in the assembled pattern failed")]
    DetectionError,
    #[fail(display = "assembly of the pattern failed for all variable instantiations")]
    AssemblyFailed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObfuscationPattern {
    pattern: Vec<InstructionPattern>,
    replacement: Vec<InstructionPattern>,
}

impl ObfuscationPattern {
    pub fn new(
        pattern: Vec<InstructionPattern>,
        replacement: Vec<InstructionPattern>,
    ) -> ObfuscationPattern {
        ObfuscationPattern {
            pattern,
            replacement,
        }
    }

    pub fn instruction_patterns(&self) -> &[InstructionPattern] {
        &self.pattern
    }

    pub fn replacement(&self) -> &[InstructionPattern] {
        &self.replacement
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Register {
    RAX,
    EAX,
    RBX,
    EBX,
    RCX,
    ECX,
    RDX,
    EDX,
    RBP,
    EBP,
    RSP,
    ESP,
    RSI,
    ESI,
    RDI,
    EDI,
}

impl Register {
    pub fn all() -> &'static [Register] {
        &[
            Register::RAX,
            Register::EAX,
            Register::RBX,
            Register::EBX,
            Register::RCX,
            Register::ECX,
            Register::RDX,
            Register::EDX,
            Register::RBP,
            Register::EBP,
            Register::RSP,
            Register::ESP,
            Register::RSI,
            Register::ESI,
            Register::RDI,
            Register::EDI,
        ]
    }

    pub fn name(self) -> &'static str {
        match self {
            Register::RAX => "RAX",
            Register::EAX => "EAX",
            Register::RBX => "RBX",
            Register::EBX => "EBX",
            Register::RCX => "RCX",
            Register::ECX => "ECX",
            Register::RDX => "RDX",
            Register::EDX => "EDX",
            Register::RBP => "RBP",
            Register::EBP => "EBP",
            Register::RSP => "RSP",
            Register::ESP => "ESP",
            Register::RSI => "RSI",
            Register::ESI => "ESI",
            Register::RDI => "RDI",
            Register::EDI => "EDI",
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
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

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn typee(&self) -> VariableType {
        self.typee
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum VariableType {
    Number,
    Register,
    Length,
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct Encoding {
    parts: Vec<EncodingPart>,
    register_mappings: Vec<(String, Register)>,
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum EncodingPart {
    Fixed(Vec<u8>),
    Intermediate { length: u8, variable_name: String },
}

impl Encoding {
    fn new(parts: Vec<EncodingPart>, register_mappings: Vec<(String, Register)>) -> Encoding {
        Encoding {
            parts,
            register_mappings,
        }
    }

    fn register_mappings(&self) -> &[(String, Register)] {
        &self.register_mappings
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct InstructionPattern {
    pattern: String,
    /// List of variables in the order they appear in the pattern. Also contains duplicates.
    variables: Vec<Variable>,
}

impl InstructionPattern {
    pub fn pattern(&self) -> &str {
        &self.pattern
    }

    pub fn variables(&self) -> &[Variable] {
        &self.variables
    }

    pub fn length_variable(&self) -> Option<&Variable> {
        self.variables
            .iter()
            .find(|var| var.typee() == VariableType::Length)
    }

    pub fn unique_register_variables(&self) -> Vec<&Variable> {
        let mut vec = Vec::new();
        for register_variable in self
            .variables
            .iter()
            .filter(|v| v.typee == VariableType::Register)
        {
            if !vec.contains(&register_variable) {
                vec.push(register_variable)
            }
        }
        vec
    }

    pub fn number_variables(&self) -> impl Iterator<Item = &Variable> {
        self.variables
            .iter()
            .filter(|v| v.typee == VariableType::Number)
    }

    pub fn find_encodings(&self) -> Result<Vec<Encoding>, PatternError> {
        fn pattern_to_encodings(
            pattern: &InstructionPattern,
        ) -> Result<FxHashSet<Encoding>, PatternError> {
            fn detect_intermediate_len(encoded: &[u8]) -> Result<u8, PatternError> {
                match encoded {
                    [.., 0x0F] => Ok(1),
                    [.., 0x0F, _] => Ok(2),
                    [.., 0x0F, _, _, _] => Ok(4),
                    [.., 0x0F, _, _, _, _, _, _, _] => Ok(8),
                    _ => Err(PatternError::DetectionError),
                }
            }

            let mapped_register_tuple = |register_tuple: &[Register]| {
                pattern
                    .unique_register_variables()
                    .into_iter()
                    .zip(register_tuple.iter().cloned())
                    .collect::<Vec<_>>()
            };

            let instantiate_one_number_variables_and_detect_encoding =
                |pattern: &InstructionPattern,
                 partial_instance: &str,
                 instantiate_with: &str,
                 register_tuple: &[Register]| {
                    // FIXME: Only replace first occurence of number_variable;
                    //        doesn't matter atm as we only support one number variable...
                    let variable = pattern.number_variables().next().unwrap();
                    let instance =
                        partial_instance.replace(&variable.to_string(), instantiate_with);

                    trace!("instance: {}", instance);
                    match keystone_assemble(instance) {
                        Err(error) => {
                            trace!("assembly failed: {}", error);
                            Err(PatternError::AssemblyFailed)
                        }
                        Ok(mut encoded) => {
                            trace!("encoded: {:x?}", encoded);
                            detect_intermediate_len(&encoded.bytes).map(|intermediate_len| {
                                let mut encoding = Vec::new();
                                encoded.bytes.truncate(
                                    (encoded.size - u32::from(intermediate_len)) as usize,
                                );
                                encoding.push(EncodingPart::Fixed(encoded.bytes));
                                encoding.push(EncodingPart::Intermediate {
                                    length: intermediate_len,
                                    variable_name: variable.name.clone(),
                                });
                                Encoding::new(
                                    encoding,
                                    mapped_register_tuple(register_tuple)
                                        .into_iter()
                                        .map(|(var, reg)| (var.name.clone(), reg))
                                        .collect(),
                                )
                            })
                        }
                    }
                };

            let foreach_register_tuple = |register_tuple: &[Register]| {
                let mut instance = pattern.pattern.clone();
                for (variable, register) in mapped_register_tuple(register_tuple) {
                    instance = instance.replace(&variable.to_string(), register.name());
                }

                for len_var in pattern
                    .variables
                    .iter()
                    .filter(|var| var.typee() == VariableType::Length)
                {
                    instance = instance.replace(&len_var.to_string(), "");
                }

                match pattern.number_variables().count() {
                    0 => {
                        trace!("instance: {}", instance);
                        match keystone_assemble(instance) {
                            Err(error) => {
                                warn!("assembly failed: {}", error);
                                vec![Err(PatternError::AssemblyFailed)]
                            }
                            Ok(encoded) => {
                                trace!("encoded: {:x?}", encoded);
                                vec![Ok(Encoding::new(
                                    vec![EncodingPart::Fixed(encoded.bytes)],
                                    mapped_register_tuple(register_tuple)
                                        .into_iter()
                                        .map(|(var, reg)| (var.name.clone(), reg))
                                        .collect(),
                                ))]
                            }
                        }
                    }
                    1 => {
                        // TODO: we may have to check if 0x0F and 0xFF as some instruction have different encodings dependent on the sign
                        // Note that these are all positive numbers
                        let instantiations = ["0x0F", "0xDD0F", "0xDDDDDD0F", "0xDDDDDDDDDDDDDD0F"];
                        instantiations
                            .iter()
                            .map(|instantiation| {
                                instantiate_one_number_variables_and_detect_encoding(
                                    &pattern,
                                    &instance,
                                    instantiation,
                                    register_tuple,
                                )
                            })
                            .collect()
                    }
                    _ => unimplemented!("Multiple number variables in an instruction patterns aren't supported yet!"),
                }
            };

            let mut encoding_results: FxHashSet<Result<Encoding, PatternError>> =
                FxHashSet::default();
            apply_for_all_register_tuples(
                pattern.unique_register_variables().len(),
                &foreach_register_tuple,
                &mut encoding_results,
            );

            let mut encodings = FxHashSet::default();

            let mut assembly_failed = true;
            for result in encoding_results {
                if let Ok(encoding) = result {
                    encodings.insert(encoding);
                } else if Err(PatternError::AssemblyFailed) != result {
                    assembly_failed = false;
                }
            }

            debug!("encodings: {:x?}", encodings);

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
                    encodings.push(Encoding::new(parts, Vec::new()));
                    Ok(encodings)
                }
                Err(_) => Err(PatternError::DetectionError),
            },
            _ if self.number_variables().count() <= 1 => {
                pattern_to_encodings(self).map(|set| set.into_iter().collect())
            }
            _ => unimplemented!(
                "Multiple number variables in an instruction patterns aren't supported yet!"
            ),
        }
    }
}

impl FromStr for InstructionPattern {
    type Err = PatternError;
    fn from_str(pattern: &str) -> Result<InstructionPattern, PatternError> {
        lazy_static! {
            static ref REGEX: Regex = Regex::new(r"\$(\w+):(\w+)").unwrap();
        }

        let mut variables = Vec::new();
        let captures_iter = REGEX.captures_iter(pattern);
        for captures in captures_iter {
            let type_str = &captures[1];
            let name = captures[2].to_string();
            let typee = match type_str {
                "num" => VariableType::Number,
                "reg" => VariableType::Register,
                "len" => VariableType::Length,
                typee => return Err(PatternError::InvalidVariableType(typee.to_string())),
            };
            let var = Variable { typee, name };
            variables.push(var);
        }

        Ok(InstructionPattern {
            pattern: pattern.to_string(),
            variables,
        })
    }
}

impl Serialize for InstructionPattern {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.pattern)
    }
}

impl<'de> Deserialize<'de> for InstructionPattern {
    fn deserialize<D>(deserializer: D) -> Result<InstructionPattern, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct InstructionPatternVisitor;

        impl<'de> Visitor<'de> for InstructionPatternVisitor {
            type Value = InstructionPattern;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a valid instruction pattern")
            }

            fn visit_str<E>(self, value: &str) -> Result<InstructionPattern, E>
            where
                E: de::Error,
            {
                InstructionPattern::from_str(value).map_err(|_| {
                    E::custom(format!("failed to parse instruction pattern: {}", value))
                })
            }
        }

        deserializer.deserialize_str(InstructionPatternVisitor)
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
                VariableType::Length => "len",
            },
            self.name
        )
    }
}

fn apply_for_all_tuples<T, F, R>(
    tuple_template: &mut [T],
    missing_elements: usize,
    set: &[T],
    f: &F,
    results: &mut FxHashSet<R>,
) where
    F: Fn(&[T]) -> Vec<R>,
    T: Clone,
    R: Eq + Hash,
{
    if missing_elements == 0 {
        for r in f(tuple_template) {
            results.insert(r);
        }
    } else {
        for element in set {
            tuple_template[tuple_template.len() - missing_elements] = element.clone();
            apply_for_all_tuples(tuple_template, missing_elements - 1, set, f, results);
        }
    }
}

fn apply_for_all_register_tuples<F, R>(tuple_elements: usize, f: &F, results: &mut FxHashSet<R>)
where
    F: Fn(&[Register]) -> Vec<R>,
    R: Eq + Hash,
{
    apply_for_all_tuples(
        &mut vec![Register::RAX; tuple_elements],
        tuple_elements,
        Register::all(),
        f,
        results,
    );
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
                    variables,
                })
            );
        }
        let var = Variable::new;

        test("move eax, ebx", vec![]);
        test(
            "move $reg:a, $reg:b",
            vec![var("a", Register), var("b", Register)],
        );
        test(
            "move $reg:a, $reg:a",
            vec![var("a", Register), var("a", Register)],
        );
        test("move eax, [$num:num1]", vec![var("num1", Number)]);
        test("move eax, [$num:42]", vec![var("42", Number)]);
        assert_eq!(
            "move $n:a, $r:b".parse::<InstructionPattern>(),
            Err(PatternError::InvalidVariableType("n".to_string()))
        );
    }
}
