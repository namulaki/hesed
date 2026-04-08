//! Stdio transport: spawns a child MCP server process and communicates via stdin/stdout.
//!
//! In stdio mode the sidecar reads JSON-RPC from its own stdin, runs the interception
//! pipeline (which forwards tool calls to the child via `StdioChild`), and writes
//! responses back to its own stdout.

use crate::{config::UpstreamConfig, discovery::ToolInfo};
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout};
use tokio::sync::Mutex;

/// A handle to the child MCP server process, communicating over stdio.
pub struct StdioChild {
    stdin: Mutex<ChildStdin>,
    stdout: Mutex<BufReader<ChildStdout>>,
    _child: Child,
}

impl StdioChild {
    /// Spawn the child MCP server process.
    pub fn spawn(upstream: &UpstreamConfig) -> anyhow::Result<Self> {
        let command = upstream
            .command
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("upstream.command is required for stdio transport"))?;

        let mut cmd = tokio::process::Command::new(command);
        cmd.args(&upstream.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());

        for (k, v) in &upstream.env {
            cmd.env(k, v);
        }

        let mut child = cmd.spawn()?;
        let stdin = child.stdin.take().expect("child stdin piped");
        let stdout = child.stdout.take().expect("child stdout piped");

        tracing::info!(command = %command, "spawned child MCP server");

        Ok(Self {
            stdin: Mutex::new(stdin),
            stdout: Mutex::new(BufReader::new(stdout)),
            _child: child,
        })
    }

    /// Send a JSON-RPC message to the child and read one line response.
    pub async fn request(&self, body: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut stdin = self.stdin.lock().await;
        stdin.write_all(body).await?;
        if !body.ends_with(b"\n") {
            stdin.write_all(b"\n").await?;
        }
        stdin.flush().await?;
        drop(stdin);

        let mut stdout = self.stdout.lock().await;
        let mut line = String::new();
        let n = stdout.read_line(&mut line).await?;
        if n == 0 {
            anyhow::bail!("child process closed stdout");
        }

        Ok(line.trim_end().as_bytes().to_vec())
    }

    /// Send a notification (no response expected).
    pub async fn notify(&self, body: &[u8]) -> anyhow::Result<()> {
        let mut stdin = self.stdin.lock().await;
        stdin.write_all(body).await?;
        if !body.ends_with(b"\n") {
            stdin.write_all(b"\n").await?;
        }
        stdin.flush().await?;
        Ok(())
    }

    /// Discover tools by sending tools/list to the child.
    pub async fn discover_tools(&self) -> Vec<ToolInfo> {
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "__discovery__",
            "method": "tools/list"
        });
        let bytes = serde_json::to_vec(&payload).unwrap();

        match self.request(&bytes).await {
            Ok(resp_bytes) => {
                let body: serde_json::Value = match serde_json::from_slice(&resp_bytes) {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(err = %e, "stdio discovery: parse error");
                        return Vec::new();
                    }
                };
                let tools: Vec<ToolInfo> = body
                    .get("result")
                    .and_then(|r| r.get("tools"))
                    .and_then(|t| serde_json::from_value(t.clone()).ok())
                    .unwrap_or_default();
                tracing::info!(count = tools.len(), "discovered upstream tools (stdio)");
                tools
            }
            Err(e) => {
                tracing::warn!(err = %e, "stdio discovery: failed");
                Vec::new()
            }
        }
    }
}

/// Run the stdio sidecar loop: read from our stdin, intercept, forward to child, write to our stdout.
pub async fn run_stdio_loop(
    state: std::sync::Arc<crate::proxy::SidecarState>,
) -> anyhow::Result<()> {
    use tokio::io::AsyncWriteExt;

    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut reader = BufReader::new(stdin);

    tracing::info!("stdio sidecar loop started");

    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            tracing::info!("stdin closed, shutting down stdio loop");
            break;
        }

        let raw = line.trim_end();
        if raw.is_empty() {
            continue;
        }

        let raw_bytes = raw.as_bytes();

        // Parse to check if notification
        let parsed: serde_json::Value = match serde_json::from_slice(raw_bytes) {
            Ok(v) => v,
            Err(_) => {
                let err = serde_json::json!({
                    "jsonrpc": "2.0", "id": null,
                    "error": {"code": -32700, "message": "Parse error"}
                });
                let b = serde_json::to_vec(&err).unwrap();
                stdout.write_all(&b).await?;
                stdout.write_all(b"\n").await?;
                stdout.flush().await?;
                continue;
            }
        };

        let is_notification = parsed.get("id").is_none();
        let method = parsed.get("method").and_then(|m| m.as_str()).unwrap_or("");

        if is_notification {
            // Forward notification to child, no response
            if let Some(ref child) = state.stdio_child {
                let _ = child.notify(raw_bytes).await;
            }
            continue;
        }

        if method == "tools/call" {
            // Run through the full interception pipeline.
            // proxy::handle_request will call forward_upstream, which in stdio mode
            // delegates to the StdioChild.
            let response_bytes = crate::proxy::handle_request(&state, raw_bytes).await;
            stdout.write_all(&response_bytes).await?;
            stdout.write_all(b"\n").await?;
            stdout.flush().await?;
        } else {
            // Non-tool-call (initialize, tools/list, etc.) — forward to child directly
            if let Some(ref child) = state.stdio_child {
                match child.request(raw_bytes).await {
                    Ok(resp) => {
                        stdout.write_all(&resp).await?;
                        stdout.write_all(b"\n").await?;
                        stdout.flush().await?;
                    }
                    Err(e) => {
                        let id = parsed.get("id").cloned();
                        let err = serde_json::json!({
                            "jsonrpc": "2.0", "id": id,
                            "error": {"code": -32603, "message": format!("child error: {}", e)}
                        });
                        let b = serde_json::to_vec(&err).unwrap();
                        stdout.write_all(&b).await?;
                        stdout.write_all(b"\n").await?;
                        stdout.flush().await?;
                    }
                }
            } else {
                // No child — forward via HTTP (shouldn't happen in stdio mode)
                let response_bytes = crate::proxy::handle_request(&state, raw_bytes).await;
                stdout.write_all(&response_bytes).await?;
                stdout.write_all(b"\n").await?;
                stdout.flush().await?;
            }
        }
    }

    Ok(())
}
