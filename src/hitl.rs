use crate::config::HitlConfig;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
struct ApprovalRequest {
    tool: String,
    role: String,
    params_summary: String,
    request_id: String,
}

#[derive(Debug, Deserialize)]
struct ApprovalResponse {
    approved: bool,
}

/// Check if a tool requires human-in-the-loop approval.
pub fn requires_approval(config: &HitlConfig, tool: &str) -> bool {
    config.enabled && config.high_risk_tools.iter().any(|t| t == tool)
}

/// Send an approval request to the configured webhook and wait for response.
pub async fn request_approval(
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
        // If webhook is unreachable or errors, deny by default
        tracing::warn!(
            status = %resp.status(),
            "HITL webhook returned non-success, denying by default"
        );
        Ok(false)
    }
}
