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
    central_url: Option<String>,
    api_key: Option<String>,
}

impl AuditLogger {
    pub fn new(config: &AuditConfig, central_url: Option<String>, api_key: Option<String>) -> Self {
        Self {
            config: config.clone(),
            client: reqwest::Client::new(),
            central_url,
            api_key,
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

        // Forward to central backend if configured
        if let Some(ref base_url) = self.central_url {
            let url = format!("{}/api/audit", base_url);
            let unique_id = format!("{}-{}", event.request_id, event.stage);
            let payload = serde_json::json!({
                "id": unique_id,
                "timestamp": event.timestamp,
                "stage": event.stage,
                "action": event.action,
                "detail": event.detail,
                "tool": event.tool,
                "role": event.role,
            });
            let mut req = self.client
                .post(&url)
                .header("content-type", "application/json")
                .json(&payload);
            if let Some(ref key) = self.api_key {
                req = req.header("authorization", format!("Bearer {}", key));
            }
            if let Err(e) = req.send().await
            {
                tracing::warn!("failed to forward audit event to central: {}", e);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_event_new() {
        let event = AuditEvent::new("req-1", "authz", "allow", "role admin allowed");
        assert_eq!(event.request_id, "req-1");
        assert_eq!(event.stage, "authz");
        assert_eq!(event.action, "allow");
        assert_eq!(event.detail, "role admin allowed");
        assert!(event.tool.is_none());
        assert!(event.role.is_none());
        assert!(!event.timestamp.is_empty());
    }

    #[test]
    fn audit_event_with_tool_and_role() {
        let event = AuditEvent::new("req-2", "dlp", "redact", "email found")
            .with_tool("jira_search")
            .with_role("developer");
        assert_eq!(event.tool, Some("jira_search".into()));
        assert_eq!(event.role, Some("developer".into()));
    }

    #[test]
    fn audit_event_serializes_to_json() {
        let event = AuditEvent::new("req-3", "breaker", "rate_limit", "exceeded")
            .with_tool("db_write");
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"request_id\":\"req-3\""));
        assert!(json.contains("\"stage\":\"breaker\""));
        assert!(json.contains("\"tool\":\"db_write\""));
    }

    #[test]
    fn append_to_file_creates_and_writes() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_str().unwrap();
        AuditLogger::append_to_file(path, "line1").unwrap();
        AuditLogger::append_to_file(path, "line2").unwrap();
        let content = std::fs::read_to_string(path).unwrap();
        assert!(content.contains("line1"));
        assert!(content.contains("line2"));
    }

    #[tokio::test]
    async fn logger_disabled_does_nothing() {
        let config = AuditConfig {
            enabled: false,
            sink: "stdout".into(),
            file_path: None,
            webhook_url: None,
        };
        let logger = AuditLogger::new(&config, None, None);
        let event = AuditEvent::new("req-4", "test", "allow", "noop");
        // Should not panic or error
        logger.log(&event).await;
    }

    #[tokio::test]
    async fn logger_file_sink() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_str().unwrap().to_string();
        let config = AuditConfig {
            enabled: true,
            sink: "file".into(),
            file_path: Some(path.clone()),
            webhook_url: None,
        };
        let logger = AuditLogger::new(&config, None, None);
        let event = AuditEvent::new("req-5", "test", "allow", "file test");
        logger.log(&event).await;
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("req-5"));
    }
}
