# hesed

A security sidecar proxy for [MCP (Model Context Protocol)](https://modelcontextprotocol.io/) tool calls. It sits between your AI agent and MCP tool servers, enforcing authorization, data loss prevention, rate limiting, and human-in-the-loop approval — with full audit logging.

## Architecture

```
User → Agent → [hesed: Interceptor → Breaker → AuthZ → DLP → (HITL?) → Tool] → Agent → User
```

Every JSON-RPC `tools/call` request passes through a security pipeline:

| Stage | What it does |
|---|---|
| Protocol Interceptor | Parses JSON-RPC, routes tool calls into the pipeline |
| Circuit Breaker | Token-bucket rate limiting via `governor` — cheapest gate, runs first |
| Policy Engine (AuthZ) | RBAC evaluation — checks if the caller's role is allowed to invoke the tool |
| Semantic Inspector (DLP) | Regex-based PII detection and redaction on both request and response payloads |
| Human-in-the-Loop | Sends high-risk tool calls to a webhook for approval before execution |
| Audit Logger | Logs every decision to stdout, file, or central dashboard |

Non-tool-call methods (e.g. `tools/list`, `resources/read`) are passed through to upstream unmodified.

## Config-Pull Architecture

The sidecar pulls all security rules (roles, DLP patterns, HITL rules) from the [hesed-pro](https://github.com/apridosimarmata/hesed-pro) dashboard on every heartbeat tick. The dashboard is the single source of truth — **no static rules in `config.toml`**.

1. Sidecar starts with empty rules
2. Every `interval_secs`, POSTs heartbeat to `/api/agents/heartbeat`
3. Immediately GETs `/api/config` to fetch roles, DLP patterns, HITL rules
4. Fetched rules replace in-memory config via `RwLock`
5. Changes in the dashboard take effect on the next heartbeat (default: 30s)

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

The sidecar's `config.toml` only needs connectivity settings. Security rules are pulled from the central dashboard.

```toml
[server]
listen_addr = "127.0.0.1:8080"

[upstream]
url = "http://127.0.0.1:3000"   # Your MCP tool server

# Rules (authz, dlp, hitl) are pulled from the central dashboard.
# No static rules here — the dashboard is the single source of truth.

[breaker]
requests_per_second = 50
burst_size = 100

[audit]
enabled = true
sink = "stdout"   # "stdout" | "file" | "central"

[heartbeat]
central_url = "http://127.0.0.1:9001"
interval_secs = 30
api_key = "hsk_your_api_key_here"
```

> **Note:** The `[authz]`, `[dlp]`, and `[hitl]` sections are optional and ignored when a heartbeat is configured. All rules come from the dashboard via `GET /api/config`.

## How Roles Work

The sidecar checks the `X-Hesed-Role` header on each request. If no role header is present, it defaults to `"default"`. Roles and their allowed tools are managed in the hesed-pro dashboard.

## Human-in-the-Loop

When a tool is listed as high-risk (configured in the dashboard), the sidecar POSTs an approval request to the configured webhook URL. The webhook must respond with:

```json
{ "approved": true }
```

If the webhook returns `approved: false` or any error, the request is denied with `ApprovalDenied`.

## Docker

```bash
docker build -t hesed .
docker run -p 8080:8080 -v $(pwd)/config.toml:/app/config.toml hesed
```

Use `0.0.0.0:8080` as `listen_addr` inside Docker so the port mapping works correctly.

## Project Structure

```
src/
├── main.rs          # HTTP server entrypoint (hyper)
├── proxy.rs         # Pipeline orchestration with RwLock-guarded dynamic config
├── interceptor.rs   # JSON-RPC types, InterceptError enum, parsing
├── authz.rs         # RBAC policy engine
├── dlp.rs           # PII/payload regex scanner & redactor
├── breaker.rs       # Rate limiter (governor)
├── hitl.rs          # Human-in-the-loop webhook
├── heartbeat.rs     # Heartbeat + config-pull from central dashboard
├── audit.rs         # Audit event logger
└── config.rs        # TOML config loader (connectivity only)
```

## License

MIT — see [LICENSE](LICENSE).
