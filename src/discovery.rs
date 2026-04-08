use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// A tool exposed by the upstream MCP server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInfo {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default, rename = "inputSchema")]
    pub input_schema: Option<serde_json::Value>,
}

/// Send `tools/list` to the upstream MCP server and return the discovered tools.
/// Returns an empty vec on any failure (network, parse, etc.) so the sidecar
/// keeps running even if the upstream isn't ready yet.
pub async fn discover_tools(
    http_client: &reqwest::Client,
    upstream_url: &str,
) -> Vec<ToolInfo> {
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list"
    });

    let resp = match http_client
        .post(upstream_url)
        .header("content-type", "application/json")
        .json(&payload)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(err = %e, "tool discovery: upstream unreachable");
            return Vec::new();
        }
    };

    if !resp.status().is_success() {
        tracing::warn!(status = %resp.status(), "tool discovery: upstream returned error");
        return Vec::new();
    }

    let body: serde_json::Value = match resp.json().await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(err = %e, "tool discovery: failed to parse response");
            return Vec::new();
        }
    };

    // MCP tools/list response: { "result": { "tools": [ { "name": ..., "description": ... } ] } }
    let tools: Vec<ToolInfo> = body
        .get("result")
        .and_then(|r| r.get("tools"))
        .and_then(|t| serde_json::from_value(t.clone()).ok())
        .unwrap_or_default();

    tracing::info!(count = tools.len(), "discovered upstream tools");
    tools
}

/// Refresh the discovered tools in the sidecar state.
/// Uses stdio child if available, otherwise falls back to HTTP discovery.
pub async fn refresh(state: &Arc<crate::proxy::SidecarState>) {
    let tools = if let Some(ref child) = state.stdio_child {
        child.discover_tools().await
    } else {
        discover_tools(&state.http_client, &state.config.upstream.url).await
    };
    let mut lock = state.discovered_tools.write().await;
    *lock = tools;
}
