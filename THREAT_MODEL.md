# Threat Model - hesed MCP Security Sidecar

## System Overview

hesed is a reverse-proxy sidecar that intercepts JSON-RPC traffic between AI agents and MCP tool servers. Every `tools/call` request passes through a security pipeline:

```
Agent → [Interceptor → Breaker → AuthZ → DLP → HITL → Upstream Tool] → Agent
```

This document enumerates threats against each stage, their impact, and the mitigations hesed provides (or should provide).

---

## Trust Boundaries

| Boundary | Description |
|---|---|
| Agent ↔ hesed | The agent is semi-trusted - it follows instructions but may be manipulated via prompt injection |
| hesed ↔ Upstream MCP | The upstream tool server is untrusted - it may return sensitive data or behave unexpectedly |
| Config file ↔ hesed | The config is fully trusted - whoever controls `config.toml` controls all policy |
| HITL webhook ↔ hesed | The webhook endpoint is trusted to return honest approve/deny decisions |

---

## Threat Catalog

### T1 - Malformed JSON-RPC Bypass

**Stage:** Interceptor  
**Threat:** An agent sends a malformed or ambiguous JSON-RPC payload that the interceptor fails to parse, causing the request to bypass the security pipeline entirely.  
**Impact:** Full pipeline bypass - no AuthZ, DLP, or rate limiting applied.  
**Mitigation:** hesed rejects any payload that fails `serde_json` deserialization with a JSON-RPC error response (`-32700 Parse error`). Non-tool-call methods are passed through but never touch the security pipeline.  
**Residual risk:** Low. Serde strict parsing covers this well.

---

### T2 - Method Name Confusion

**Stage:** Interceptor  
**Threat:** An agent sends a tool call using an unexpected method name (e.g. `tools_call` instead of `tools/call`) that the interceptor doesn't recognize as a tool invocation, causing it to be forwarded without policy checks.  
**Impact:** AuthZ, DLP, and HITL bypass for the misrouted call.  
**Mitigation:** hesed only applies the pipeline to `tools/call` - all other methods are passed through by design. This is correct behavior per MCP spec.  
**Residual risk:** Low, assuming the upstream MCP server only executes tools via `tools/call`.

---

### T3 - Role Spoofing / Privilege Escalation

**Stage:** AuthZ  
**Threat:** The agent (or a prompt injection attack) crafts a request that claims a higher-privilege role (e.g. `admin`) in the `params` or headers, bypassing RBAC restrictions.  
**Impact:** Unauthorized tool execution.  
**Mitigation:** hesed extracts the role from the JSON-RPC `params` field. The role-to-tool mapping is defined in `config.toml` and cannot be overridden by the request itself. However, if the role value in the request is attacker-controlled, the attacker can claim any role.  
**Residual risk:** **High.** Role assignment is currently trust-based - there is no cryptographic binding (e.g. signed JWT) between the caller identity and the role. A compromised or prompt-injected agent can claim any role.

**Recommendation:** Introduce signed role tokens or integrate with an external identity provider to bind roles to verified identities.

---

### T4 - Wildcard Role Misconfiguration

**Stage:** AuthZ  
**Threat:** An operator configures a role with `allowed_tools = ["*"]`, inadvertently granting access to all tools including destructive ones.  
**Impact:** Over-permissive access - defeats the purpose of RBAC.  
**Mitigation:** This is a configuration issue, not a code bug. hesed faithfully enforces whatever policy is configured.  
**Residual risk:** Medium. Operator error.

**Recommendation:** Log a warning at startup when wildcard roles are detected. Consider a `--strict` mode that rejects wildcard bindings.

---

### T5 - DLP Pattern Evasion

**Stage:** DLP  
**Threat:** Sensitive data is encoded, obfuscated, or split across multiple fields to evade regex-based PII detection (e.g. base64-encoded SSN, Unicode homoglyphs, zero-width characters, or splitting `123-45-6789` across two params).  
**Impact:** PII leakage in tool call arguments or responses.  
**Mitigation:** hesed applies regex patterns to the serialized JSON string of params/results. This catches plaintext PII but not encoded forms.  
**Residual risk:** **High.** Regex-based DLP is inherently bypassable by encoding. This is a known limitation of pattern-matching approaches.

**Recommendation:** Document this limitation clearly. For high-security deployments, consider adding base64 decode-and-scan, Unicode normalization, or integration with a dedicated DLP service.

---

### T6 - DLP Redaction Side Effects

**Stage:** DLP  
**Threat:** Aggressive regex redaction corrupts tool call parameters (e.g. replacing a number that looks like an SSN but is actually a valid tool argument), causing the upstream tool to fail or behave unexpectedly.  
**Impact:** Availability degradation - legitimate tool calls broken by false-positive redaction.  
**Mitigation:** Operators must tune DLP patterns carefully. hesed applies the configured `redact_replacement` string uniformly.  
**Residual risk:** Medium. Depends on pattern quality.

---

### T7 - Rate Limit Exhaustion (DoS)

**Stage:** Circuit Breaker  
**Threat:** A compromised or runaway agent floods hesed with requests, exhausting the token bucket and causing legitimate requests to be rate-limited.  
**Impact:** Denial of service for legitimate tool calls.  
**Mitigation:** hesed uses `governor` with a configurable `requests_per_second` and `burst_size`. Excess requests receive a JSON-RPC error (`-32000`).  
**Residual risk:** Medium. The rate limiter is global (not per-role or per-agent), so one bad actor starves everyone.

**Recommendation:** Add per-role or per-agent rate limiting to isolate blast radius.

---

### T8 - HITL Webhook Spoofing

**Stage:** Human-in-the-Loop  
**Threat:** An attacker intercepts or spoofs the HITL webhook response, sending a fake "approved" decision for a high-risk tool call.  
**Impact:** Unauthorized execution of high-risk tools (e.g. `rm`, `exec`, `deploy`).  
**Mitigation:** hesed sends a POST to the configured `webhook_url` and trusts the response. There is no signature verification or shared secret on the webhook response.  
**Residual risk:** **High** if the webhook is over HTTP or the network is untrusted.

**Recommendation:** Add HMAC signature verification on webhook responses. Enforce HTTPS for webhook URLs. Consider a nonce/challenge to prevent replay attacks.

---

### T9 - HITL Timeout / Availability

**Stage:** Human-in-the-Loop  
**Threat:** The HITL webhook is unavailable (network issue, Slack outage, etc.), causing tool calls to hang indefinitely or fail open.  
**Impact:** Either availability loss (hang) or security bypass (fail-open).  
**Mitigation:** hesed uses `reqwest` with a 30-second timeout. On timeout or error, the request is denied.  
**Residual risk:** Low for security (fail-closed). Medium for availability.

---

### T10 - Audit Log Tampering

**Stage:** Audit  
**Threat:** An attacker with access to the audit sink (stdout, file, or webhook) modifies or deletes audit logs to cover their tracks.  
**Impact:** Loss of forensic evidence - security incidents go undetected.  
**Mitigation:** hesed writes audit events but does not protect the sink itself. File-based logs have no integrity protection. Webhook-based sinks depend on the receiver's security.  
**Residual risk:** Medium. Standard log-tampering risk.

**Recommendation:** For high-security deployments, use append-only log sinks (e.g. S3 with Object Lock, immutable Kafka topics) or sign audit entries with HMAC.

---

### T11 - Config File Tampering

**Stage:** All  
**Threat:** An attacker modifies `config.toml` to disable security controls (e.g. set `hitl.enabled = false`, add wildcard roles, remove DLP patterns).  
**Impact:** Complete security bypass.  
**Mitigation:** hesed reads config at startup and trusts it entirely. No runtime integrity checks.  
**Residual risk:** **High** if the config file is writable by untrusted users.

**Recommendation:** Restrict file permissions (`chmod 600`). Consider config signing or checksum verification at startup.

---

### T12 - Upstream Response Injection

**Stage:** Proxy (post-upstream)  
**Threat:** A malicious or compromised upstream MCP server returns a crafted response containing prompt injection payloads, PII, or instructions that manipulate the agent's subsequent behavior.  
**Impact:** Agent compromise via indirect prompt injection. PII leakage to the agent/user.  
**Mitigation:** hesed applies DLP redaction to upstream responses before returning them to the agent. This catches plaintext PII but not encoded injection payloads.  
**Residual risk:** **High.** DLP does not detect prompt injection content - it only matches PII patterns.

**Recommendation:** Consider adding response content inspection for known prompt injection patterns. This is an active research area.

---

### T13 - TLS / Network Eavesdropping

**Stage:** Agent ↔ hesed, hesed ↔ Upstream  
**Threat:** An attacker on the network intercepts plaintext traffic between the agent and hesed, or between hesed and the upstream tool server.  
**Impact:** Credential theft, PII exposure, request/response tampering.  
**Mitigation:** hesed listens on a local address (`127.0.0.1`) by default, limiting exposure. However, it does not terminate TLS - both the agent-facing and upstream connections are plaintext HTTP.  
**Residual risk:** Low for localhost deployments. **High** for networked deployments without a TLS terminator in front.

**Recommendation:** Add native TLS support or document the requirement for a TLS-terminating reverse proxy (e.g. nginx, envoy) in production.

---

### T14 - Dependency Supply Chain

**Stage:** Build  
**Threat:** A compromised crate in the dependency tree introduces malicious code into the hesed binary.  
**Impact:** Arbitrary code execution, data exfiltration, backdoor.  
**Mitigation:** `Cargo.lock` pins exact versions. Dependencies are well-known crates (`tokio`, `hyper`, `serde`, `governor`, `reqwest`).  
**Residual risk:** Low but non-zero. Standard supply chain risk.

**Recommendation:** Run `cargo audit` in CI. Consider `cargo-vet` for dependency review.

---

## Risk Summary

| ID | Threat | Severity | Residual Risk |
|---|---|---|---|
| T1 | Malformed JSON-RPC bypass | Medium | Low |
| T2 | Method name confusion | Medium | Low |
| T3 | Role spoofing | High | **High** |
| T4 | Wildcard misconfiguration | Medium | Medium |
| T5 | DLP pattern evasion | High | **High** |
| T6 | DLP redaction side effects | Medium | Medium |
| T7 | Rate limit exhaustion | Medium | Medium |
| T8 | HITL webhook spoofing | High | **High** |
| T9 | HITL timeout | Medium | Low |
| T10 | Audit log tampering | Medium | Medium |
| T11 | Config file tampering | Critical | **High** |
| T12 | Upstream response injection | High | **High** |
| T13 | TLS / network eavesdropping | High | Context-dependent |
| T14 | Dependency supply chain | Medium | Low |

---

## Priority Recommendations

1. **Signed role tokens** (T3) - bind roles to cryptographic identity, not request params
2. **HITL webhook authentication** (T8) - HMAC signatures + HTTPS enforcement
3. **Config file protection** (T11) - file permissions, optional integrity check
4. **TLS support** (T13) - native or documented proxy requirement
5. **Per-agent rate limiting** (T7) - isolate blast radius
6. **DLP limitations documentation** (T5) - set clear expectations for operators
