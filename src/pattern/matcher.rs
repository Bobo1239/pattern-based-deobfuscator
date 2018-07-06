use regex::bytes::Regex;

use pattern::*;

#[derive(Debug, Clone)]
pub struct ObfuscationPatternMatcher {
    instruction_pattern_matchers: Vec<InstructionPatternMatcher>,
    regex: Regex,
}

impl ObfuscationPatternMatcher {
    pub fn new(
        instruction_patterns: Vec<InstructionPattern>,
    ) -> Result<ObfuscationPatternMatcher, PatternError> {
        let instruction_pattern_matchers = instruction_patterns
            .into_iter()
            .map(InstructionPatternMatcher::new)
            .collect::<Result<Vec<_>, _>>()?;

        // regex flags:
        //    s: allow . to match \n
        //   -u: disable unicode support (allow matches even when not at a unicode boundary)
        let regex = format!(
            "(?s-u){}",
            instruction_pattern_matchers
                .iter()
                .map(|ipm| &*ipm.regex)
                .collect::<Vec<_>>()
                .join("")
        );
        debug!("obfuscation pattern regex: {}", regex);
        let regex = Regex::new(&regex).unwrap();

        Ok(ObfuscationPatternMatcher {
            instruction_pattern_matchers,
            regex,
        })
    }

    pub fn instruction_patterns(&self) -> Vec<InstructionPattern> {
        self.instruction_pattern_matchers
            .iter()
            .map(|ipm| ipm.pattern.clone())
            .collect()
    }

    /// Returns the found matches where each match contains information about the matched variables,
    /// the start position, and the end position
    pub fn match_against(&self, bytes: &[u8]) -> Vec<(Vec<InstantiatedVariable>, usize, usize)> {
        debug!("regex: {}", self.regex.as_str());
        debug!("match against: {:x?}", bytes);
        self.regex
            .captures_iter(bytes)
            .map(|captures| {
                trace!("new capture ----------");
                let whole_match = captures.get(0).unwrap();
                // need to offset the capture group purpose index as the indices in the
                // `InstructionPatternMatcher`s are only valid in their own capture group
                let mut capture_group_offset = 1;

                struct InstantiatedVariableStore(Vec<InstantiatedVariable>);
                impl InstantiatedVariableStore {
                    fn try_add(&mut self, new_variable: InstantiatedVariable) -> bool {
                        // TODO: change to better data structure?
                        match self.0.iter().find(|var| var.name() == new_variable.name()) {
                            Some(existing) => &new_variable == existing,
                            None => {
                                info!("Rejected match because variable value changed.");
                                self.0.push(new_variable);
                                true
                            }
                        }
                    }
                }

                let mut instantiated_variables = InstantiatedVariableStore(Vec::new());

                'outer: for k in 0..self.instruction_pattern_matchers.len() {
                    trace!("capture_group_offset: {:?}", capture_group_offset);
                    for i in 1.. {
                        // Iterate through the different encoding capture groups of this instruction
                        // pattern
                        // This will definitely terminate as regex.captures(bytes) only returns `Some` if
                        // it matched and then an encoding capture group must have participated in the match
                        if let CaptureGroupPurpose::NewEncoding(ref register_mappings) =
                            self.instruction_pattern_matchers[k].capture_group_purposes[i]
                        {
                            trace!("getting capture group {}", i + capture_group_offset);
                            if captures.get(i + capture_group_offset).is_some() {
                                // Found the matched encoding; Extract the number variables and return result

                                for j in (i + 1).. {
                                    trace!(
                                        "inner getting capture group {}",
                                        j + capture_group_offset
                                    );
                                    match self.instruction_pattern_matchers[k]
                                        .capture_group_purposes
                                        .get(j)
                                    {
                                        None | Some(CaptureGroupPurpose::NewEncoding(_)) => {
                                            // Also add register variable instantiations
                                            for (variable_name, register) in register_mappings {
                                                // FIXME: first check if there's already in instantiation for
                                                // this variable and if there is, make sure it has the same value
                                                // Change to two HashMaps? (one for each var type)
                                                if !instantiated_variables.try_add(
                                                    InstantiatedVariable::new_register(
                                                        variable_name.to_string(),
                                                        *register,
                                                    ),
                                                ) {
                                                    return None;
                                                }
                                            }
                                            if k == self.instruction_pattern_matchers.len() - 1 {
                                                // matched all instruction patterns; success!
                                                return Some((
                                                    instantiated_variables.0,
                                                    whole_match.start(),
                                                    whole_match.end(),
                                                ));
                                            } else {
                                                capture_group_offset += self
                                                    .instruction_pattern_matchers[k]
                                                    .capture_group_purposes
                                                    .len();
                                                continue 'outer;
                                            }
                                        }
                                        Some(CaptureGroupPurpose::NumberVariable(
                                            variable_name,
                                        )) => {
                                            let bytes = &captures[j + capture_group_offset];
                                            assert!(bytes.len() <= 4);
                                            let mut value = 0;
                                            for byte in bytes.iter().rev() {
                                                value <<= 8;
                                                value += u64::from(*byte);
                                            }
                                            // FIXME: first check if there's already in instantiation for
                                            // this variable and if there is, make sure it has the same value
                                            if !instantiated_variables.try_add(
                                                InstantiatedVariable::new_number(
                                                    variable_name.to_string(),
                                                    value,
                                                ),
                                            ) {
                                                return None;
                                            }
                                        }
                                        Some(CaptureGroupPurpose::WholeMatch) => unreachable!(),
                                    }
                                }
                            }
                        }
                    }
                }
                unreachable!()
            })
            .filter_map(|opt| opt)
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct InstructionPatternMatcher {
    pattern: InstructionPattern,
    regex: String,
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
        (format!("({})", regexes.join("|")), capture_group_purposes)
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

    pub fn name(&self) -> &str {
        match self {
            InstantiatedVariable::Number(name, _) => name,
            InstantiatedVariable::Register(name, _) => name,
        }
    }

    pub fn typee(&self) -> VariableType {
        match self {
            InstantiatedVariable::Number(..) => VariableType::Number,
            InstantiatedVariable::Register(..) => VariableType::Register,
        }
    }
}
