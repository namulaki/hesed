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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_valid_request() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"jira_search"}}"#;
        let req = parse_request(body).unwrap();
        assert_eq!(req.jsonrpc, "2.0");
        assert_eq!(req.method, "tools/call");
        assert_eq!(req.id, Some(json!(1)));
    }

    #[test]
    fn parse_invalid_json() {
        let body = b"not json at all";
        let err = parse_request(body);
        assert!(err.is_err());
        assert!(matches!(err.unwrap_err(), InterceptError::InvalidPayload(_)));
    }

    #[test]
    fn parse_empty_body() {
        let err = parse_request(b"");
        assert!(err.is_err());
    }

    #[test]
    fn extract_tool_name_tools_call() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: Some(json!(1)),
            method: "tools/call".into(),
            params: Some(json!({"name": "db_write", "arguments": {}})),
        };
        assert_eq!(extract_tool_name(&req), Some("db_write".into()));
    }

    #[test]
    fn extract_tool_name_non_tools_call() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: Some(json!(1)),
            method: "tools/list".into(),
            params: Some(json!({"name": "db_write"})),
        };
        assert_eq!(extract_tool_name(&req), None);
    }

    #[test]
    fn extract_tool_name_no_params() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: Some(json!(1)),
            method: "tools/call".into(),
            params: None,
        };
        assert_eq!(extract_tool_name(&req), None);
    }

    #[test]
    fn extract_tool_name_missing_name_field() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: Some(json!(1)),
            method: "tools/call".into(),
            params: Some(json!({"arguments": {}})),
        };
        assert_eq!(extract_tool_name(&req), None);
    }

    #[test]
    fn error_codes() {
        assert_eq!(InterceptError::InvalidPayload("x".into()).code(), -32700);
        assert_eq!(InterceptError::AuthzDenied("x".into()).code(), -32600);
        assert_eq!(InterceptError::RateLimited.code(), -32000);
        assert_eq!(InterceptError::ApprovalDenied("x".into()).code(), -32001);
        assert_eq!(InterceptError::Upstream("x".into()).code(), -32603);
    }

    #[test]
    fn error_into_response() {
        let resp = InterceptError::RateLimited.into_response(Some(json!(42)));
        assert_eq!(resp.jsonrpc, "2.0");
        assert_eq!(resp.id, Some(json!(42)));
        assert!(resp.result.is_none());
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32000);
        assert!(err.message.contains("rate limit"));
    }

    #[test]
    fn error_into_response_null_id() {
        let resp = InterceptError::AuthzDenied("denied".into()).into_response(None);
        assert!(resp.id.is_none());
        assert_eq!(resp.error.unwrap().code, -32600);
    }

    #[test]
    fn jsonrpc_request_roundtrip() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: Some(json!(1)),
            method: "tools/call".into(),
            params: Some(json!({"name": "test"})),
        };
        let serialized = serde_json::to_string(&req).unwrap();
        let deserialized: JsonRpcRequest = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.method, "tools/call");
    }
}

