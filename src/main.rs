mod audit;
mod authz;
mod breaker;
mod config;
mod discovery;
mod dlp;
mod heartbeat;
mod hitl;
mod interceptor;
mod proxy;
mod stdio;

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::signal::unix::SignalKind;
use tracing_subscriber::EnvFilter;

async fn handle(
    state: Arc<proxy::SidecarState>,
    req: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let limit = state.config.server.max_request_body_bytes as usize;
    let limited = Limited::new(req.into_body(), limit);

    let body = match limited.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            let err_resp = interceptor::JsonRpcResponse {
                jsonrpc: "2.0".into(),
                id: None,
                result: None,
                error: Some(interceptor::JsonRpcError {
                    code: -32600,
                    message: format!("request body exceeds maximum size of {} bytes", limit),
                    data: None,
                }),
            };
            let err_bytes = serde_json::to_vec(&err_resp).unwrap();
            return Ok(Response::builder()
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from(err_bytes)))
                .unwrap());
        }
    };

    let response_bytes = proxy::handle_request(&state, &body).await;
    Ok(Response::builder()
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(response_bytes)))
        .unwrap())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Init tracing
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("mcp_sidecar=info".parse()?))
        .json()
        .init();

    // Load config
    let config_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("config.toml"));

    let cfg = config::Config::load(&config_path)?;
    let is_stdio = cfg.transport == config::TransportMode::Stdio;

    tracing::info!(
        transport = ?cfg.transport,
        mode = ?cfg.mode,
        "starting mcp-sidecar"
    );

    // Build state — in stdio mode, spawn the child process first
    let mut state = proxy::SidecarState::new(cfg.clone())?;
    if is_stdio {
        let child = stdio::StdioChild::spawn(&cfg.upstream)?;
        state.stdio_child = Some(Arc::new(child));
    }
    let state = Arc::new(state);

    // Discover upstream tools on startup (best-effort, non-blocking on failure)
    discovery::refresh(&state).await;

    // Start heartbeat only in dynamic mode
    if cfg.mode == config::ConfigMode::Dynamic {
        if let Some(hb_config) = cfg.heartbeat {
            heartbeat::spawn(
                state.clone(),
                hb_config.central_url,
                hb_config.interval_secs,
                cfg.upstream.url.clone(),
                hb_config.api_key,
            );
        } else {
            tracing::warn!("dynamic mode requires [heartbeat] config — falling back to static rules");
        }
    } else {
        tracing::info!("static mode — using rules from config file only");
    }

    // Branch on transport mode
    if is_stdio {
        // Stdio mode: read from our stdin, intercept, forward to child, write to our stdout
        stdio::run_stdio_loop(state).await?;
    } else {
        // HTTP mode: run the HTTP server
        let addr: SocketAddr = cfg.server.listen_addr.parse()?;
        let listener = TcpListener::bind(addr).await?;
        tracing::info!("listening on {}", addr);

        let mut join_set = tokio::task::JoinSet::new();
        let mut sigterm = tokio::signal::unix::signal(SignalKind::terminate())?;

        loop {
            tokio::select! {
                result = listener.accept() => {
                    let (stream, _) = result?;
                    let io = TokioIo::new(stream);
                    let state = state.clone();
                    join_set.spawn(async move {
                        if let Err(err) = http1::Builder::new()
                            .serve_connection(io, service_fn(move |req| handle(state.clone(), req)))
                            .await
                        {
                            tracing::error!("connection error: {:?}", err);
                        }
                    });
                }
                _ = tokio::signal::ctrl_c() => {
                    tracing::info!(in_flight = join_set.len(), "received SIGINT, starting graceful shutdown");
                    break;
                }
                _ = sigterm.recv() => {
                    tracing::info!(in_flight = join_set.len(), "received SIGTERM, starting graceful shutdown");
                    break;
                }
            }
        }

        let timeout_secs = cfg.server.shutdown_timeout_secs;
        let drain_result = tokio::time::timeout(
            std::time::Duration::from_secs(timeout_secs),
            async {
                while join_set.join_next().await.is_some() {}
            },
        )
        .await;

        if drain_result.is_err() {
            tracing::warn!(remaining = join_set.len(), "shutdown timeout reached, aborting remaining connections");
            join_set.shutdown().await;
        }
    }

    tracing::info!("shutdown complete");
    Ok(())
}
