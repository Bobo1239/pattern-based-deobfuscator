use pattern::InstructionPattern;

// #[derive(Serialize, Deserialize)]
pub struct ObfuscationPattern {
    pattern: Vec<InstructionPattern>,
    replacement: Vec<InstructionPattern>,
}

pub struct PatternDatabase {
    patterns: Vec<ObfuscationPattern>,
}
