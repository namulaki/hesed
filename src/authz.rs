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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthzConfig, RoleBinding};
    use serde_json::json;

    fn test_config() -> AuthzConfig {
        AuthzConfig {
            roles: vec![
                RoleBinding {
                    role: "admin".into(),
                    allowed_tools: vec!["*".into()],
                },
                RoleBinding {
                    role: "developer".into(),
                    allowed_tools: vec!["jira_search".into(), "github_pr".into()],
                },
                RoleBinding {
                    role: "default".into(),
                    allowed_tools: vec!["jira_search".into()],
                },
            ],
        }
    }

    #[test]
    fn admin_wildcard_allows_any_tool() {
        assert!(evaluate(&test_config(), "admin", "anything"));
        assert!(evaluate(&test_config(), "admin", "db_delete"));
    }

    #[test]
    fn developer_allowed_tools() {
        assert!(evaluate(&test_config(), "developer", "jira_search"));
        assert!(evaluate(&test_config(), "developer", "github_pr"));
    }

    #[test]
    fn developer_denied_unlisted_tool() {
        assert!(!evaluate(&test_config(), "developer", "db_delete"));
    }

    #[test]
    fn default_role_limited() {
        assert!(evaluate(&test_config(), "default", "jira_search"));
        assert!(!evaluate(&test_config(), "default", "github_pr"));
    }

    #[test]
    fn unknown_role_denied() {
        assert!(!evaluate(&test_config(), "unknown", "jira_search"));
    }

    #[test]
    fn extract_role_from_meta() {
        let params = json!({"_meta": {"role": "admin"}, "name": "test"});
        assert_eq!(extract_role(Some(&params)), "admin");
    }

    #[test]
    fn extract_role_missing_meta() {
        let params = json!({"name": "test"});
        assert_eq!(extract_role(Some(&params)), "default");
    }

    #[test]
    fn extract_role_none_params() {
        assert_eq!(extract_role(None), "default");
    }

    #[test]
    fn extract_role_non_string() {
        let params = json!({"_meta": {"role": 42}});
        assert_eq!(extract_role(Some(&params)), "default");
    }
}
