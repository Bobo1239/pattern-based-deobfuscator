#![allow(dead_code)]

use std::fmt::{self, Display};

use regex::Regex;

#[derive(Debug, PartialEq)]
pub struct Variable {
    name: String,
    typee: VariableType,
}

impl Variable {
    fn new(name: &str, typee: VariableType) -> Variable {
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
struct RegexPart();

// fn add_instruction_to_regex(regex: &mut String) {

// }

#[derive(Debug, PartialEq)]
pub struct InstructionPattern {
    pattern: String,
    variables: Vec<Variable>, // ordered
}

impl<'a> From<&'a str> for InstructionPattern {
    fn from(s: &str) -> Self {
        lazy_static! {
            static ref REGEX: Regex = Regex::new(r"\$(num|reg):(\w+)").unwrap();
        }

        let mut vec = Vec::new();
        let captures_iter = REGEX.captures_iter(s);
        for captures in captures_iter {
            let type_str = &captures[1];
            let name = captures[2].to_string();
            let typee = match type_str {
                "num" => VariableType::Number,
                "reg" => VariableType::Register,
                _ => unreachable!(),
            };
            let var = Variable { typee, name };
            if !vec.contains(&var) {
                vec.push(var);
            }
        }

        InstructionPattern {
            pattern: s.to_string(),
            variables: vec,
        }
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

// -> Vec<RegexPart> // different encodings e.g. depending on operand size
// fn find_operand(instruction: &str, var: Variable) -> Option<> {

// }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_instruction_pattern() {
        use super::VariableType::*;
        fn test(pattern: &str, variables: Vec<Variable>) {
            assert_eq!(
                InstructionPattern::from(pattern),
                InstructionPattern {
                    pattern: pattern.to_string(),
                    variables: variables,
                }
            );
        }
        fn var(name: &str, typee: VariableType) -> Variable {
            Variable::new(name, typee)
        }

        test("move eax, ebx", vec![]);
        test(
            "move $reg:a, $reg:b",
            vec![var("a", Register), var("b", Register)],
        );
        test("move $reg:a, $reg:a", vec![var("a", Register)]);
        test("move eax, [$num:num1]", vec![var("num1", Number)]);
        test("move eax, [$num:42]", vec![var("42", Number)]);
        test("move $n:a, $r:b", vec![]);
    }
}
