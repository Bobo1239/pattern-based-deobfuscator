use regex::bytes::Regex;

use pattern::*;

#[derive(Debug, Clone)]
pub struct InstructionPatternMatcher {
    pattern: InstructionPattern,
    regex: Regex,
    /// Mapping from the index of a regex capture group number to either the whole match, a
    /// variable, or a start of a new encoding (which indicates the register variable
    /// instantiations). Note that always only a continous range of capture groups will be captured
    /// (start of encoding and the variables in that encoding until a new encoding starts)
    capture_group_purposes: Vec<CaptureGroupPurpose>,
}

impl InstructionPatternMatcher {
    pub fn new(pattern: InstructionPattern) -> Result<InstructionPatternMatcher, PatternError> {
        let encodings = pattern.find_encodings()?;

        let (regex, capture_group_purposes) = Self::encodings_to_regex(&encodings);
        let regex = Regex::new(&regex).unwrap();

        Ok(InstructionPatternMatcher {
            pattern,
            regex,
            capture_group_purposes,
        })
    }

    fn encodings_to_regex(encodings: &[Encoding]) -> (String, Vec<CaptureGroupPurpose>) {
        let mut capture_group_purposes = Vec::new();
        capture_group_purposes.push(CaptureGroupPurpose::WholeMatch); // group 0 corresponds to the full match

        let regexes: Vec<_> = encodings
            .iter()
            .map(|enc| Self::encoding_to_regex(&mut capture_group_purposes, enc))
            .collect();
        // regex flags:
        //    s: allow . to match \n
        //   -u: disable unicode support (allow matches even when not at a unicode boundary)
        (
            format!("(?s-u)^{}", &regexes.join("|")),
            capture_group_purposes,
        )
    }

    fn encoding_to_regex(
        capture_group_purposes: &mut Vec<CaptureGroupPurpose>,
        encoding: &Encoding,
    ) -> String {
        let mut regex = String::new();
        regex.push('(');
        capture_group_purposes.push(CaptureGroupPurpose::NewEncoding(
            encoding.register_mappings().to_vec(),
        ));
        for part in &encoding.parts {
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
                    regex.push('(');
                    capture_group_purposes.push(CaptureGroupPurpose::NumberVariable(
                        variable_name.to_string(),
                    ));
                    for _ in 0..*length {
                        regex.push('.');
                    }
                    regex.push(')');
                }
            }
        }
        regex.push(')');
        regex
    }

    pub fn pattern(&self) -> &InstructionPattern {
        &self.pattern
    }

    /// Returns the matched [Variable]s and the number of bytes that got matched
    pub fn match_against(&self, bytes: &[u8]) -> Option<(Vec<InstantiatedVariable>, u8)> {
        debug!("regex: {}", self.regex.as_str());
        debug!("capture group purposes: {:?}", self.capture_group_purposes);
        debug!("match against: {:x?}", bytes);
        self.regex.captures(bytes).map(|captures| {
            for i in 1.. {
                // This will definitely terminate as regex.captures(bytes) only returns some if
                // it matched and then an encoding capture group must have participated in the match
                if let CaptureGroupPurpose::NewEncoding(ref register_mappings) =
                    self.capture_group_purposes[i]
                {
                    if let Some(whole_match) = captures.get(i) {
                        // Found the matched encoding; Extract the number variables and return result
                        let matched_length = (whole_match.end() - whole_match.start()) as u8;

                        let mut instantiated_variables = Vec::new();
                        for j in (i + 1).. {
                            match self.capture_group_purposes.get(j) {
                                None | Some(CaptureGroupPurpose::NewEncoding(_)) => {
                                    // Also add register variable instantiations
                                    for (variable_name, register) in register_mappings {
                                        instantiated_variables.push(
                                            InstantiatedVariable::new_register(
                                                variable_name.to_string(),
                                                *register,
                                            ),
                                        );
                                    }
                                    return (instantiated_variables, matched_length);
                                }
                                Some(CaptureGroupPurpose::NumberVariable(variable_name)) => {
                                    let bytes = &captures[j];
                                    assert!(bytes.len() <= 4);
                                    let mut value = 0;
                                    for byte in bytes.iter().rev() {
                                        value <<= 8;
                                        value += u64::from(*byte);
                                    }
                                    instantiated_variables.push(InstantiatedVariable::new_number(
                                        variable_name.to_string(),
                                        value,
                                    ))
                                }
                                Some(CaptureGroupPurpose::WholeMatch) => unreachable!(),
                            }
                        }
                    }
                }
            }
            unreachable!()
        })
    }
}

#[derive(Debug, Clone)]
enum CaptureGroupPurpose {
    /// Capture group corresponds to a number variable
    NumberVariable(String),
    /// Capture group starts a new encoding. The `Vec` contains the values of the register variables
    NewEncoding(Vec<(String, Register)>),
    /// Capture group corresponds to the whole match (capture group 0)
    WholeMatch,
}

#[derive(Debug, Clone, PartialEq)]
pub enum InstantiatedVariable {
    Number(String, u64),
    Register(String, Register),
}

impl InstantiatedVariable {
    pub fn new_number(name: String, value: u64) -> InstantiatedVariable {
        InstantiatedVariable::Number(name, value)
    }

    pub fn new_register(name: String, value: Register) -> InstantiatedVariable {
        InstantiatedVariable::Register(name, value)
    }
}
