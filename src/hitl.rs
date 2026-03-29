use crate::config::HitlConfig;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
struct ApprovalRequest {
    tool: String,
    role: String,
    params_summary: String,
    request_id: String,
    agent_id: String,
}

#[derive(Debug, Deserialize)]
struct ApprovalResponse {
    approved: bool,
}

#[derive(Debug, Deserialize)]
struct CentralApprovalResponse {
    id: String,
    status: String, // "pending" | "approved" | "denied"
}

/// Check if a tool requires human-in-the-loop approval.
pub fn requires_approval(config: &HitlConfig, tool: &str) -> bool {
    config.enabled && config.high_risk_tools.iter().any(|t| t == tool)
}

/// Request approval via the central dashboard (UI-based HITL).
/// Posts the request, then polls until the human decides or timeout.
pub async fn request_approval_central(
    central_url: &str,
    api_key: &str,
    agent_id: &str,
    tool: &str,
    role: &str,
    params: &serde_json::Value,
    request_id: &str,
) -> anyhow::Result<bool> {
    let client = reqwest::Client::new();
    let base = central_url.trim_end_matches('/');

    // 1. Create the approval request on the dashboard
    let payload = ApprovalRequest {
        tool: tool.to_string(),
        role: role.to_string(),
        params_summary: serde_json::to_string(params).unwrap_or_default(),
        request_id: request_id.to_string(),
        agent_id: agent_id.to_string(),
    };

    let resp = client
        .post(format!("{}/api/approvals", base))
        .header("authorization", format!("Bearer {}", api_key))
        .json(&payload)
        .send()
        .await?;

    if !resp.status().is_success() {
        tracing::warn!(status = %resp.status(), "failed to create approval request");
        return Ok(false);
    }

    let created: CentralApprovalResponse = resp.json().await?;
    let poll_url = format!("{}/api/approvals/{}", base, created.id);

    // 2. Poll for decision (2s interval, 5min timeout)
    let timeout = tokio::time::Duration::from_secs(300);
    let poll_interval = tokio::time::Duration::from_secs(2);
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        tokio::time::sleep(poll_interval).await;

        if tokio::time::Instant::now() > deadline {
            tracing::warn!(request_id = %request_id, "HITL approval timed out");
            return Ok(false);
        }

        let poll_resp = client
            .get(&poll_url)
            .header("authorization", format!("Bearer {}", api_key))
            .send()
            .await;

        match poll_resp {
            Ok(r) if r.status().is_success() => {
                let entry: CentralApprovalResponse = r.json().await?;
                match entry.status.as_str() {
                    "approved" => return Ok(true),
                    "denied" => return Ok(false),
                    _ => continue, // still pending
                }
            }
            Ok(r) => {
                tracing::warn!(status = %r.status(), "approval poll error");
                continue;
            }
            Err(e) => {
                tracing::warn!(err = %e, "approval poll failed");
                continue;
            }
        }
    }
}

/// Send an approval request to the configured webhook and wait for response.
/// Legacy webhook-based HITL — kept for backward compatibility.
pub async fn request_approval_webhook(
    config: &HitlConfig,
    tool: &str,
    role: &str,
    params: &serde_json::Value,
    request_id: &str,
) -> anyhow::Result<bool> {
    let client = reqwest::Client::new();
    let payload = ApprovalRequest {
        tool: tool.to_string(),
        role: role.to_string(),
        params_summary: serde_json::to_string(params).unwrap_or_default(),
        request_id: request_id.to_string(),
        agent_id: String::new(),
    };

    let resp = client
        .post(&config.webhook_url)
        .json(&payload)
        .send()
        .await?;

    if resp.status().is_success() {
        let body: ApprovalResponse = resp.json().await?;
        Ok(body.approved)
    } else {
        tracing::warn!(
            status = %resp.status(),
            "HITL webhook returned non-success, denying by default"
        );
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::HitlConfig;

    fn enabled_config() -> HitlConfig {
        HitlConfig {
            enabled: true,
            high_risk_tools: vec!["db_write".into(), "db_delete".into(), "github_merge".into()],
            webhook_url: "http://localhost:9090/approve".into(),
        }
    }

    fn disabled_config() -> HitlConfig {
        HitlConfig {
            enabled: false,
            high_risk_tools: vec!["db_write".into()],
            webhook_url: "http://localhost:9090/approve".into(),
        }
    }

    #[test]
    fn requires_approval_high_risk_tool() {
        assert!(requires_approval(&enabled_config(), "db_write"));
        assert!(requires_approval(&enabled_config(), "db_delete"));
        assert!(requires_approval(&enabled_config(), "github_merge"));
    }

    #[test]
    fn no_approval_for_safe_tool() {
        assert!(!requires_approval(&enabled_config(), "jira_search"));
        assert!(!requires_approval(&enabled_config(), "github_pr"));
    }

    #[test]
    fn no_approval_when_disabled() {
        assert!(!requires_approval(&disabled_config(), "db_write"));
    }

    #[test]
    fn no_approval_empty_tools() {
        let config = HitlConfig {
            enabled: true,
            high_risk_tools: vec![],
            webhook_url: "http://localhost:9090".into(),
        };
        assert!(!requires_approval(&config, "db_write"));
    }
}
