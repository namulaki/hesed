use crate::{audit, authz, breaker, config::Config, dlp, hitl, interceptor};
use crate::interceptor::InterceptError;
use std::sync::Arc;
use uuid::Uuid;

pub struct SidecarState {
    pub config: Config,
    pub dlp_engine: dlp::DlpEngine,
    pub limiter: breaker::Limiter,
    pub audit_logger: audit::AuditLogger,
    pub http_client: reqwest::Client,
}

impl SidecarState {
    pub fn new(config: Config) -> anyhow::Result<Self> {
        let dlp_engine = dlp::DlpEngine::new(&config.dlp)?;
        let limiter = breaker::new_limiter(config.breaker.requests_per_second, config.breaker.burst_size)?;
        let audit_logger = audit::AuditLogger::new(&config.audit);
        let http_client = reqwest::Client::new();
        Ok(Self { config, dlp_engine, limiter, audit_logger, http_client })
    }
}

/// Main pipeline: Intercept → AuthZ → DLP → Breaker → (HITL?) → Upstream → DLP response → Return
pub async fn handle_request(state: &Arc<SidecarState>, body: &[u8]) -> Vec<u8> {
    let request_id = Uuid::new_v4().to_string();

    match pipeline(state, body, &request_id).await {
        Ok(response_bytes) => response_bytes,
        Err(err) => {
            // Try to extract the request id for the JSON-RPC response
            let req_id = interceptor::parse_request(body)
                .ok()
                .and_then(|r| r.id);
            serde_json::to_vec(&err.into_response(req_id)).unwrap_or_default()
        }
    }
}

/// The actual pipeline, returning InterceptError on any stage failure
async fn pipeline(
    state: &Arc<SidecarState>,
    body: &[u8],
    request_id: &str,
) -> Result<Vec<u8>, InterceptError> {
    // 1. Parse JSON-RPC
    let req = interceptor::parse_request(body)?;
    let tool_name = interceptor::extract_tool_name(&req);

    // Log intercept
    let mut evt = audit::AuditEvent::new(request_id, "intercept", "received", &req.method);
    if let Some(ref t) = tool_name {
        evt = evt.with_tool(t);
    }
    state.audit_logger.log(&evt).await;

    // For non-tool-call methods, pass through directly
    let tool = match tool_name {
        Some(t) => t,
        None => return forward_upstream(state, body, request_id).await,
    };

    // 2. AuthZ - extract role and evaluate
    let role = authz::extract_role(req.params.as_ref());
    if !authz::evaluate(&state.config.authz, &role, &tool) {
        state.audit_logger.log(
            &audit::AuditEvent::new(request_id, "authz", "deny", &format!("role={} tool={}", role, tool))
                .with_tool(&tool).with_role(&role)
        ).await;
        return Err(InterceptError::AuthzDenied(
            format!("role '{}' on tool '{}'", role, tool),
        ));
    }
    state.audit_logger.log(
        &audit::AuditEvent::new(request_id, "authz", "allow", &format!("role={} tool={}", role, tool))
            .with_tool(&tool).with_role(&role)
    ).await;

    // 3. DLP - sanitize request params
    let mut sanitized_req = req.clone();
    if let Some(ref mut params) = sanitized_req.params {
        let detections = state.dlp_engine.detect(&params.to_string());
        if !detections.is_empty() {
            state.audit_logger.log(
                &audit::AuditEvent::new(request_id, "dlp", "redact", &format!("detected: {:?}", detections))
                    .with_tool(&tool)
            ).await;
            state.dlp_engine.sanitize_value(params);
        }
    }

    // 4. Circuit Breaker - rate limit check
    if !breaker::check(&state.limiter) {
        state.audit_logger.log(
            &audit::AuditEvent::new(request_id, "breaker", "rate_limit", "request throttled")
                .with_tool(&tool)
        ).await;
        return Err(InterceptError::RateLimited);
    }

    // 5. HITL - human-in-the-loop for high-risk tools
    if hitl::requires_approval(&state.config.hitl, &tool) {
        state.audit_logger.log(
            &audit::AuditEvent::new(request_id, "hitl", "pending", &format!("awaiting approval for {}", tool))
                .with_tool(&tool)
        ).await;

        let params = sanitized_req.params.as_ref().cloned().unwrap_or(serde_json::Value::Null);
        match hitl::request_approval(&state.config.hitl, &tool, &role, &params, request_id).await {
            Ok(true) => {
                state.audit_logger.log(
                    &audit::AuditEvent::new(request_id, "hitl", "approve", "human approved")
                        .with_tool(&tool)
                ).await;
            }
            Ok(false) => {
                state.audit_logger.log(
                    &audit::AuditEvent::new(request_id, "hitl", "reject", "human denied")
                        .with_tool(&tool)
                ).await;
                return Err(InterceptError::ApprovalDenied("human denied".into()));
            }
            Err(e) => {
                state.audit_logger.log(
                    &audit::AuditEvent::new(request_id, "hitl", "reject", &format!("webhook error: {}", e))
                        .with_tool(&tool)
                ).await;
                return Err(InterceptError::ApprovalDenied(format!("webhook error: {}", e)));
            }
        }
    }

    // 6. Forward to upstream MCP tool server
    let upstream_body = serde_json::to_vec(&sanitized_req).unwrap_or_default();
    let mut response_bytes = forward_upstream(state, &upstream_body, request_id).await?;

    // 7. DLP - sanitize response
    if let Ok(mut resp_value) = serde_json::from_slice::<serde_json::Value>(&response_bytes) {
        state.dlp_engine.sanitize_value(&mut resp_value);
        response_bytes = serde_json::to_vec(&resp_value).unwrap_or(response_bytes);
    }

    state.audit_logger.log(
        &audit::AuditEvent::new(request_id, "upstream", "allow", "response returned")
            .with_tool(&tool)
    ).await;

    Ok(response_bytes)
}

async fn forward_upstream(
    state: &Arc<SidecarState>,
    body: &[u8],
    request_id: &str,
) -> Result<Vec<u8>, InterceptError> {
    let resp = state.http_client
        .post(&state.config.upstream.url)
        .header("content-type", "application/json")
        .body(body.to_vec())
        .send()
        .await;

    match resp {
        Ok(r) => Ok(r.bytes().await.unwrap_or_default().to_vec()),
        Err(e) => {
            tracing::error!(request_id = %request_id, "upstream error: {}", e);
            Err(InterceptError::Upstream(e.to_string()))
        }
    }
}
