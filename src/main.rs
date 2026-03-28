mod audit;
mod authz;
mod breaker;
mod config;
mod dlp;
mod hitl;
mod interceptor;
mod proxy;

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

async fn handle(
    state: Arc<proxy::SidecarState>,
    req: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let body = req.collect().await?.to_bytes();
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
    let addr: SocketAddr = cfg.server.listen_addr.parse()?;

    tracing::info!(listen = %addr, upstream = %cfg.upstream.url, "starting mcp-sidecar");

    let state = Arc::new(proxy::SidecarState::new(cfg)?);
    let listener = TcpListener::bind(addr).await?;

    tracing::info!("listening on {}", addr);

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let state = state.clone();

        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .serve_connection(io, service_fn(move |req| handle(state.clone(), req)))
                .await
            {
                tracing::error!("connection error: {:?}", err);
            }
        });
    }
}
