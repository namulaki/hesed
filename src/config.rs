use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub server: ServerConfig,
    pub upstream: UpstreamConfig,
    #[serde(default)]
    pub authz: AuthzConfig,
    #[serde(default)]
    pub dlp: DlpConfig,
    pub breaker: BreakerConfig,
    #[serde(default)]
    pub hitl: HitlConfig,
    pub audit: AuditConfig,
    pub heartbeat: Option<HeartbeatConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub listen_addr: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct UpstreamConfig {
    pub url: String,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct AuthzConfig {
    #[serde(default)]
    pub roles: Vec<RoleBinding>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RoleBinding {
    pub role: String,
    pub allowed_tools: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DlpConfig {
    #[serde(default)]
    pub patterns: Vec<DlpPattern>,
    #[serde(default = "default_redact")]
    pub redact_replacement: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DlpPattern {
    pub name: String,
    pub regex: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct BreakerConfig {
    pub requests_per_second: u32,
    pub burst_size: u32,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct HitlConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub high_risk_tools: Vec<String>,
    #[serde(default)]
    pub webhook_url: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AuditConfig {
    pub enabled: bool,
    pub sink: String, // "stdout" | "file" | "webhook"
    pub file_path: Option<String>,
    pub webhook_url: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct HeartbeatConfig {
    pub central_url: String,
    #[serde(default = "default_interval")]
    pub interval_secs: u64,
    pub api_key: Option<String>,
}

fn default_interval() -> u64 {
    30
}

fn default_redact() -> String {
    "[REDACTED]".to_string()
}

impl Default for DlpConfig {
    fn default() -> Self {
        Self {
            patterns: Vec::new(),
            redact_replacement: default_redact(),
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn valid_toml() -> &'static str {
        r#"
[server]
listen_addr = "127.0.0.1:8080"

[upstream]
url = "http://localhost:3000"

[authz]
[[authz.roles]]
role = "admin"
allowed_tools = ["*"]

[dlp]
redact_replacement = "[REDACTED]"
[[dlp.patterns]]
name = "email"
regex = '[a-z]+@[a-z]+\.[a-z]+'

[breaker]
requests_per_second = 50
burst_size = 100

[hitl]
enabled = true
high_risk_tools = ["db_write"]
webhook_url = "http://localhost:9090/approve"

[audit]
enabled = true
sink = "stdout"
"#
    }

    #[test]
    fn load_valid_config() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        write!(tmp, "{}", valid_toml()).unwrap();
        let config = Config::load(tmp.path()).unwrap();
        assert_eq!(config.server.listen_addr, "127.0.0.1:8080");
        assert_eq!(config.upstream.url, "http://localhost:3000");
        assert_eq!(config.authz.roles.len(), 1);
        assert_eq!(config.authz.roles[0].role, "admin");
        assert_eq!(config.dlp.redact_replacement, "[REDACTED]");
        assert_eq!(config.breaker.requests_per_second, 50);
        assert!(config.hitl.enabled);
        assert!(config.audit.enabled);
    }

    #[test]
    fn load_missing_file() {
        let result = Config::load(Path::new("/nonexistent/config.toml"));
        assert!(result.is_err());
    }

    #[test]
    fn load_invalid_toml() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        write!(tmp, "this is not valid toml {{{{").unwrap();
        let result = Config::load(tmp.path());
        assert!(result.is_err());
    }

    #[test]
    fn load_missing_required_fields() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        write!(tmp, "[server]\nlisten_addr = \"127.0.0.1:8080\"").unwrap();
        let result = Config::load(tmp.path());
        assert!(result.is_err());
    }

    #[test]
    fn deserialize_role_binding() {
        let toml_str = r#"role = "dev"
allowed_tools = ["jira", "github"]"#;
        let rb: RoleBinding = toml::from_str(toml_str).unwrap();
        assert_eq!(rb.role, "dev");
        assert_eq!(rb.allowed_tools, vec!["jira", "github"]);
    }

    #[test]
    fn audit_config_optional_fields() {
        let toml_str = r#"enabled = false
sink = "stdout""#;
        let ac: AuditConfig = toml::from_str(toml_str).unwrap();
        assert!(!ac.enabled);
        assert!(ac.file_path.is_none());
        assert!(ac.webhook_url.is_none());
    }
}
