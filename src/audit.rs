use crate::config::AuditConfig;
use chrono::Utc;
use serde::Serialize;
use std::io::Write;

#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    pub timestamp: String,
    pub request_id: String,
    pub stage: String,      // "intercept" | "authz" | "dlp" | "breaker" | "hitl" | "upstream"
    pub tool: Option<String>,
    pub role: Option<String>,
    pub action: String,     // "allow" | "deny" | "redact" | "rate_limit" | "approve" | "reject"
    pub detail: String,
}

impl AuditEvent {
    pub fn new(request_id: &str, stage: &str, action: &str, detail: &str) -> Self {
        Self {
            timestamp: Utc::now().to_rfc3339(),
            request_id: request_id.to_string(),
            stage: stage.to_string(),
            tool: None,
            role: None,
            action: action.to_string(),
            detail: detail.to_string(),
        }
    }

    pub fn with_tool(mut self, tool: &str) -> Self {
        self.tool = Some(tool.to_string());
        self
    }

    pub fn with_role(mut self, role: &str) -> Self {
        self.role = Some(role.to_string());
        self
    }
}

pub struct AuditLogger {
    config: AuditConfig,
    client: reqwest::Client,
}

impl AuditLogger {
    pub fn new(config: &AuditConfig) -> Self {
        Self {
            config: config.clone(),
            client: reqwest::Client::new(),
        }
    }

    pub async fn log(&self, event: &AuditEvent) {
        if !self.config.enabled {
            return;
        }

        let json = match serde_json::to_string(event) {
            Ok(j) => j,
            Err(e) => {
                tracing::error!("failed to serialize audit event: {}", e);
                return;
            }
        };

        match self.config.sink.as_str() {
            "stdout" => {
                tracing::info!(audit = %json);
            }
            "file" => {
                if let Some(path) = &self.config.file_path {
                    if let Err(e) = Self::append_to_file(path, &json) {
                        tracing::error!("failed to write audit log to file: {}", e);
                    }
                }
            }
            "webhook" => {
                if let Some(url) = &self.config.webhook_url {
                    if let Err(e) = self.client.post(url).body(json).send().await {
                        tracing::error!("failed to send audit event to webhook: {}", e);
                    }
                }
            }
            other => {
                tracing::warn!("unknown audit sink: {}", other);
            }
        }
    }

    fn append_to_file(path: &str, line: &str) -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        writeln!(file, "{}", line)?;
        Ok(())
    }
}
