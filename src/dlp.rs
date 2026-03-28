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
