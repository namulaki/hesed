use crate::proxy::SidecarState;
use serde::Serialize;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::time::{interval, Duration};

#[derive(Serialize)]
struct HeartbeatPayload {
    agent_id: String,
    hostname: String,
    version: String,
    upstream_url: Option<String>,
    total_requests: u64,
    blocked_requests: u64,
}

/// Spawns a background task that sends heartbeats to the central hesed-pro server.
pub fn spawn(
    state: Arc<SidecarState>,
    central_url: String,
    interval_secs: u64,
    upstream_url: String,
    api_key: Option<String>,
) {
    let agent_id = format!("agent-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let hostname = hostname();
    let version = env!("CARGO_PKG_VERSION").to_string();

    tokio::spawn(async move {
        let url = format!("{}/api/agents/heartbeat", central_url.trim_end_matches('/'));
        let mut tick = interval(Duration::from_secs(interval_secs));

        tracing::info!(
            agent_id = %agent_id,
            central = %central_url,
            interval = interval_secs,
            "heartbeat started"
        );

        loop {
            tick.tick().await;

            let payload = HeartbeatPayload {
                agent_id: agent_id.clone(),
                hostname: hostname.clone(),
                version: version.clone(),
                upstream_url: Some(upstream_url.clone()),
                total_requests: state.total_requests.load(Ordering::Relaxed),
                blocked_requests: state.blocked_requests.load(Ordering::Relaxed),
            };

            let mut req = state.http_client.post(&url).json(&payload);
            if let Some(ref key) = api_key {
                req = req.header("authorization", format!("Bearer {}", key));
            }
            match req.send().await {
                Ok(r) if r.status().is_success() => {
                    tracing::debug!("heartbeat sent");
                }
                Ok(r) => {
                    tracing::warn!(status = %r.status(), "heartbeat rejected");
                }
                Err(e) => {
                    tracing::warn!(err = %e, "heartbeat failed");
                }
            }
        }
    });
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| gethostname())
}

fn gethostname() -> String {
    #[cfg(unix)]
    {
        use std::ffi::CStr;
        let mut buf = [0u8; 256];
        unsafe {
            libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len());
            CStr::from_ptr(buf.as_ptr() as *const libc::c_char)
                .to_string_lossy()
                .into_owned()
        }
    }
    #[cfg(not(unix))]
    {
        "unknown".to_string()
    }
}
