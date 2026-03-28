use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: Option<serde_json::Value>,
    pub method: String,
    pub params: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

#[derive(Debug, Error)]
pub enum InterceptError {
    #[error("invalid JSON-RPC payload: {0}")]
    InvalidPayload(String),
    #[error("authorization denied: {0}")]
    AuthzDenied(String),
    #[error("rate limit exceeded")]
    RateLimited,
    #[error("approval denied: {0}")]
    ApprovalDenied(String),
    #[error("upstream error: {0}")]
    Upstream(String),
}

impl InterceptError {
    /// JSON-RPC error code for each variant
    pub fn code(&self) -> i64 {
        match self {
            Self::InvalidPayload(_) => -32700, // Parse error
            Self::AuthzDenied(_) => -32600,    // Invalid request
            Self::RateLimited => -32000,       // Server error (custom)
            Self::ApprovalDenied(_) => -32001, // Server error (custom)
            Self::Upstream(_) => -32603,       // Internal error
        }
    }

    /// Convert into a JSON-RPC error response, using the request's id if available
    pub fn into_response(self, id: Option<serde_json::Value>) -> JsonRpcResponse {
        JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code: self.code(),
                message: self.to_string(),
                data: None,
            }),
        }
    }
}

/// Parse raw bytes into a JSON-RPC request
pub fn parse_request(body: &[u8]) -> Result<JsonRpcRequest, InterceptError> {
    serde_json::from_slice(body)
        .map_err(|e| InterceptError::InvalidPayload(e.to_string()))
}

/// Extract the tool name from a tools/call request
pub fn extract_tool_name(req: &JsonRpcRequest) -> Option<String> {
    if req.method == "tools/call" {
        req.params
            .as_ref()
            .and_then(|p| p.get("name"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    } else {
        None
    }
}

