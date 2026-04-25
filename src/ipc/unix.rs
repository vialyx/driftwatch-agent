//! Unix Domain Socket IPC server (macOS + Linux).
//!
//! Listens on `/var/run/riskagent.sock`.  Each connection receives a
//! newline-delimited JSON request and gets back a newline-delimited JSON
//! response.

use std::sync::Arc;

use anyhow::Result;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixListener,
};
use tracing::{error, info};

use super::{constant_time_eq, parse_authenticated_request, IpcRequest, IpcState};

/// Path of the Unix domain socket.
pub const SOCKET_PATH: &str = "/var/run/riskagent.sock";

/// Serve IPC requests on the Unix domain socket until the process exits.
pub async fn serve(state: Arc<IpcState>) -> Result<()> {
    // Remove stale socket file from a previous run.
    let _ = std::fs::remove_file(SOCKET_PATH);

    if let Some(parent) = std::path::Path::new(SOCKET_PATH).parent() {
        std::fs::create_dir_all(parent)?;
    }

    let listener = UnixListener::bind(SOCKET_PATH)?;
    #[cfg(unix)]
    {
        std::fs::set_permissions(SOCKET_PATH, std::fs::Permissions::from_mode(0o600))?;
    }
    info!("IPC listening on {}", SOCKET_PATH);

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let state = state.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, state).await {
                        error!("IPC connection error: {}", e);
                    }
                });
            }
            Err(e) => {
                error!("IPC accept error: {}", e);
            }
        }
    }
}

async fn handle_connection(stream: tokio::net::UnixStream, state: Arc<IpcState>) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    while let Some(line) = lines.next_line().await? {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        let response_json = dispatch(&line, &state).await;
        writer.write_all(response_json.as_bytes()).await?;
        writer.write_all(b"\n").await?;
    }

    Ok(())
}

async fn dispatch(request: &str, state: &IpcState) -> String {
    let parsed = match parse_authenticated_request(request) {
        Ok(r) => r,
        Err(e) => {
            return serde_json::to_string(&super::IpcResponse::<()>::error(format!(
                "invalid request: {}",
                e
            )))
            .unwrap_or_default();
        }
    };

    if !constant_time_eq(&parsed.token, &state.auth_token) {
        return serde_json::to_string(&super::IpcResponse::<()>::error("unauthorized"))
            .unwrap_or_default();
    }

    match parsed.request {
        IpcRequest::GetCurrent => {
            let guard = state.latest_score.read().await;
            match &*guard {
                Some(score) => serde_json::to_string(&super::IpcResponse::success(score))
                    .unwrap_or_else(|e| format!(r#"{{"ok":false,"error":"{}"}}"#, e)),
                None => serde_json::to_string(&super::IpcResponse::<()>::error("no score yet"))
                    .unwrap_or_default(),
            }
        }
        IpcRequest::GetHistory { n } => {
            let history = state.history.read().await;
            let take_n = n.max(1).min(state.history_limit);
            let scores = history
                .iter()
                .rev()
                .take(take_n)
                .cloned()
                .collect::<Vec<_>>();
            serde_json::to_string(&super::IpcResponse::success(scores))
                .unwrap_or_else(|e| format!(r#"{{"ok":false,"error":"{}"}}"#, e))
        }
        IpcRequest::GetHealth => {
            let health = state.health().await;
            serde_json::to_string(&super::IpcResponse::success(health))
                .unwrap_or_else(|e| format!(r#"{{"ok":false,"error":"{}"}}"#, e))
        }
        IpcRequest::ForceRefresh => {
            let _ = state.force_refresh_tx.send(());
            serde_json::to_string(&super::IpcResponse::success("refresh triggered"))
                .unwrap_or_default()
        }
    }
}
