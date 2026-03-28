use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub server: ServerConfig,
    pub upstream: UpstreamConfig,
    pub authz: AuthzConfig,
    pub dlp: DlpConfig,
    pub breaker: BreakerConfig,
    pub hitl: HitlConfig,
    pub audit: AuditConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub listen_addr: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct UpstreamConfig {
    pub url: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AuthzConfig {
    pub roles: Vec<RoleBinding>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RoleBinding {
    pub role: String,
    pub allowed_tools: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DlpConfig {
    pub patterns: Vec<DlpPattern>,
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

#[derive(Debug, Deserialize, Clone)]
pub struct HitlConfig {
    pub enabled: bool,
    pub high_risk_tools: Vec<String>,
    pub webhook_url: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AuditConfig {
    pub enabled: bool,
    pub sink: String, // "stdout" | "file" | "webhook"
    pub file_path: Option<String>,
    pub webhook_url: Option<String>,
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }
}
