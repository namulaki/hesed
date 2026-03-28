use crate::config::DlpConfig;
use regex::Regex;

pub struct DlpEngine {
    patterns: Vec<(String, Regex)>,
    replacement: String,
}

impl DlpEngine {
    pub fn new(config: &DlpConfig) -> anyhow::Result<Self> {
        let mut patterns = Vec::new();
        for p in &config.patterns {
            let re = Regex::new(&p.regex)?;
            patterns.push((p.name.clone(), re));
        }
        Ok(Self {
            patterns,
            replacement: config.redact_replacement.clone(),
        })
    }

    /// Scan text and return list of matched pattern names.
    pub fn detect(&self, text: &str) -> Vec<String> {
        self.patterns
            .iter()
            .filter(|(_, re)| re.is_match(text))
            .map(|(name, _)| name.clone())
            .collect()
    }

    /// Redact all matching patterns in the text.
    pub fn redact(&self, text: &str) -> String {
        let mut result = text.to_string();
        for (_, re) in &self.patterns {
            result = re.replace_all(&result, self.replacement.as_str()).to_string();
        }
        result
    }

    /// Scan and redact a JSON value recursively (string fields only).
    pub fn sanitize_value(&self, value: &mut serde_json::Value) {
        match value {
            serde_json::Value::String(s) => {
                *s = self.redact(s);
            }
            serde_json::Value::Object(map) => {
                for v in map.values_mut() {
                    self.sanitize_value(v);
                }
            }
            serde_json::Value::Array(arr) => {
                for v in arr.iter_mut() {
                    self.sanitize_value(v);
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DlpConfig, DlpPattern};
    use serde_json::json;

    fn test_config() -> DlpConfig {
        DlpConfig {
            redact_replacement: "[REDACTED]".into(),
            patterns: vec![
                DlpPattern {
                    name: "email".into(),
                    regex: r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}".into(),
                },
                DlpPattern {
                    name: "ssn".into(),
                    regex: r"\b\d{3}-\d{2}-\d{4}\b".into(),
                },
            ],
        }
    }

    #[test]
    fn new_engine_valid_patterns() {
        let engine = DlpEngine::new(&test_config());
        assert!(engine.is_ok());
    }

    #[test]
    fn new_engine_invalid_regex() {
        let config = DlpConfig {
            redact_replacement: "X".into(),
            patterns: vec![DlpPattern {
                name: "bad".into(),
                regex: "[invalid".into(),
            }],
        };
        assert!(DlpEngine::new(&config).is_err());
    }

    #[test]
    fn detect_email() {
        let engine = DlpEngine::new(&test_config()).unwrap();
        let matches = engine.detect("contact user@example.com for info");
        assert!(matches.contains(&"email".to_string()));
        assert!(!matches.contains(&"ssn".to_string()));
    }

    #[test]
    fn detect_ssn() {
        let engine = DlpEngine::new(&test_config()).unwrap();
        let matches = engine.detect("SSN is 123-45-6789");
        assert!(matches.contains(&"ssn".to_string()));
    }

    #[test]
    fn detect_nothing() {
        let engine = DlpEngine::new(&test_config()).unwrap();
        let matches = engine.detect("nothing sensitive here");
        assert!(matches.is_empty());
    }

    #[test]
    fn detect_multiple() {
        let engine = DlpEngine::new(&test_config()).unwrap();
        let matches = engine.detect("email: a@b.com ssn: 123-45-6789");
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn redact_email() {
        let engine = DlpEngine::new(&test_config()).unwrap();
        let result = engine.redact("send to user@example.com please");
        assert!(result.contains("[REDACTED]"));
        assert!(!result.contains("user@example.com"));
    }

    #[test]
    fn redact_preserves_clean_text() {
        let engine = DlpEngine::new(&test_config()).unwrap();
        let input = "nothing to redact here";
        assert_eq!(engine.redact(input), input);
    }

    #[test]
    fn sanitize_value_string() {
        let engine = DlpEngine::new(&test_config()).unwrap();
        let mut val = json!("email is user@test.com");
        engine.sanitize_value(&mut val);
        assert!(!val.as_str().unwrap().contains("user@test.com"));
    }

    #[test]
    fn sanitize_value_nested_object() {
        let engine = DlpEngine::new(&test_config()).unwrap();
        let mut val = json!({"data": {"email": "a@b.com"}, "count": 5});
        engine.sanitize_value(&mut val);
        assert!(!val["data"]["email"].as_str().unwrap().contains("a@b.com"));
        assert_eq!(val["count"], 5); // numbers untouched
    }

    #[test]
    fn sanitize_value_array() {
        let engine = DlpEngine::new(&test_config()).unwrap();
        let mut val = json!(["clean", "has 123-45-6789"]);
        engine.sanitize_value(&mut val);
        assert_eq!(val[0], "clean");
        assert!(val[1].as_str().unwrap().contains("[REDACTED]"));
    }
}
