use pattern::ObfuscationPattern;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PatternDatabase(Vec<ObfuscationPattern>);

impl PatternDatabase {
    pub fn patterns(&self) -> &[ObfuscationPattern] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json;

    use pattern::*;

    #[test]
    fn serialization_roundtrip() {
        let pattern_database = PatternDatabase(vec![ObfuscationPattern::new(
            vec![
                "lea rbp, [rip + $num:var_name1]".parse().unwrap(),
                "xchg rbp, [rsp]".parse().unwrap(),
                "ret".parse().unwrap(),
            ],
            vec!["jmp [rip + $num:var_name1]".parse().unwrap()],
        )]);

        let serialized = serde_json::to_string(&pattern_database).unwrap();
        assert_eq!(
            serde_json::from_str::<PatternDatabase>(&serialized).unwrap(),
            pattern_database
        );
    }
}
