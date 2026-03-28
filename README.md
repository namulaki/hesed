# hesed

A security sidecar proxy for [MCP (Model Context Protocol)](https://modelcontextprotocol.io/) tool calls. It sits between your AI agent and MCP tool servers, enforcing authorization, data loss prevention, rate limiting, and human-in-the-loop approval - with full audit logging.

## Architecture

```
User → Agent → [hesed: Interceptor → AuthZ → DLP → Breaker → (HITL?) → Tool] → Agent → User
```

Every JSON-RPC `tools/call` request passes through a security pipeline:

| Stage | What it does |
|---|---|
| Protocol Interceptor | Parses JSON-RPC, routes tool calls into the pipeline |
| Policy Engine (AuthZ) | RBAC evaluation - checks if the caller's role is allowed to invoke the tool |
| Semantic Inspector (DLP) | Regex-based PII detection and redaction on both request and response payloads |
| Circuit Breaker | Token-bucket rate limiting via `governor` |
| Human-in-the-Loop | Sends high-risk tool calls to a webhook (e.g. Slack) for approval before execution |
| Audit Logger | Logs every decision to stdout, file, or webhook (Kafka/Datadog compatible) |

Non-tool-call methods (e.g. `tools/list`, `resources/read`) are passed through to upstream unmodified.

## Error Handling

The pipeline uses a typed `InterceptError` enum. Each stage returns a specific error variant, which is automatically converted into a JSON-RPC error response with the correct error code:

| Error | Code | When |
|---|---|---|
| `InvalidPayload` | -32700 | Malformed JSON-RPC request |
| `AuthzDenied` | -32600 | Role not authorized for the requested tool |
| `RateLimited` | -32000 | Token bucket exhausted |
| `ApprovalDenied` | -32001 | HITL webhook rejected or failed |
| `Upstream` | -32603 | MCP tool server unreachable or errored |

Example error response:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32600,
    "message": "authorization denied: role 'viewer' on tool 'db_write'"
  }
}
```

## Quick Start

```bash
# Build
cargo build --release

# Run (defaults to config.toml in current directory)
./target/release/hesed

# Or specify a config path
./target/release/hesed /path/to/config.toml
```

## Configuration

See [`config.toml`](config.toml) for a full example. Key sections:

```toml
[server]
listen_addr = "127.0.0.1:8080"

[upstream]
url = "http://127.0.0.1:3000"   # Your MCP tool server

[authz]
[[authz.roles]]
role = "admin"
allowed_tools = ["*"]

[[authz.roles]]
role = "developer"
allowed_tools = ["jira_search", "github_pr", "db_read"]

[dlp]
redact_replacement = "[REDACTED]"

[[dlp.patterns]]
name = "email"
regex = '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'

[breaker]
requests_per_second = 50
burst_size = 100

[hitl]
enabled = true
high_risk_tools = ["db_write", "db_delete", "github_merge"]
webhook_url = "http://localhost:9090/approve"

[audit]
enabled = true
sink = "stdout"   # "stdout" | "file" | "webhook"
```

## How Roles Work

The sidecar extracts the role from the JSON-RPC request's `params._meta.role` field:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "db_read",
    "_meta": { "role": "developer" }
  }
}
```

If no role is present, it defaults to `"default"`.

## Human-in-the-Loop

When a tool is listed in `hitl.high_risk_tools`, the sidecar POSTs an approval request to the configured webhook:

```json
{
  "tool": "db_delete",
  "role": "developer",
  "params_summary": "...",
  "request_id": "uuid"
}
```

The webhook must respond with:

```json
{ "approved": true }
```

If the webhook returns `approved: false` or any error, the request is denied with `ApprovalDenied`.

## Docker

```bash
docker build -t hesed .
docker run -p 8080:8080 -v $(pwd)/config.toml:/app/config.toml hesed
```

## Project Structure

```
src/
├── main.rs          # HTTP server entrypoint (hyper)
├── proxy.rs         # Pipeline orchestration (Result<Vec<u8>, InterceptError>)
├── interceptor.rs   # JSON-RPC types, InterceptError enum, parsing
├── authz.rs         # RBAC policy engine
├── dlp.rs           # PII/payload regex scanner & redactor
├── breaker.rs       # Rate limiter (governor)
├── hitl.rs          # Human-in-the-loop webhook
├── audit.rs         # Audit event logger
└── config.rs        # TOML config loader
```

## License

MIT - see [LICENSE](LICENSE).
