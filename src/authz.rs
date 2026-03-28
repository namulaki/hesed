use crate::config::AuthzConfig;

/// Check if a given role is allowed to call the specified tool.
pub fn evaluate(config: &AuthzConfig, role: &str, tool: &str) -> bool {
    config.roles.iter().any(|binding| {
        binding.role == role
            && (binding.allowed_tools.contains(&"*".to_string())
                || binding.allowed_tools.iter().any(|t| t == tool))
    })
}

/// Extract the role from JSON-RPC request metadata (params._meta.role).
/// Falls back to "default" if not present.
pub fn extract_role(params: Option<&serde_json::Value>) -> String {
    params
        .and_then(|p| p.get("_meta"))
        .and_then(|m| m.get("role"))
        .and_then(|r| r.as_str())
        .unwrap_or("default")
        .to_string()
}
