//! Unix Domain Socket IPC server (macOS + Linux).
//!
//! Listens on `/var/run/riskagent.sock`.  Each connection receives a
//! newline-delimited JSON request and gets back a newline-delimited JSON
//! response.

use std::sync::Arc;

use anyhow::Result;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixListener,
};
use tracing::{error, info};

use super::IpcState;
use crate::scoring::RiskScore;

/// Path of the Unix domain socket.
pub const SOCKET_PATH: &str = "/var/run/riskagent.sock";

/// Serve IPC requests on the Unix domain socket until the process exits.
pub async fn serve(state: Arc<IpcState>) -> Result<()> {
    // Remove stale socket file from a previous run.
    let _ = std::fs::remove_file(SOCKET_PATH);

    let listener = UnixListener::bind(SOCKET_PATH)?;
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

async fn handle_connection(
    stream: tokio::net::UnixStream,
    state: Arc<IpcState>,
) -> Result<()> {
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
    // Simple line-based protocol: the request line is the path.
    match request {
        "GET /risk/current" => {
            let guard = state.latest_score.read().await;
            match &*guard {
                Some(score) => serde_json::to_string(&super::IpcResponse::success(score))
                    .unwrap_or_else(|e| format!(r#"{{"ok":false,"error":"{}"}}"#, e)),
                None => serde_json::to_string(&super::IpcResponse::<()>::error("no score yet"))
                    .unwrap_or_default(),
            }
        }
        s if s.starts_with("GET /risk/history") => {
            // Simplified: return latest score in a list (full history requires DB query)
            let guard = state.latest_score.read().await;
            let scores: Vec<&RiskScore> = guard.iter().collect();
            serde_json::to_string(&super::IpcResponse::success(scores))
                .unwrap_or_else(|e| format!(r#"{{"ok":false,"error":"{}"}}"#, e))
        }
        "POST /risk/force-refresh" => {
            let _ = state.force_refresh_tx.send(());
            serde_json::to_string(&super::IpcResponse::success("refresh triggered"))
                .unwrap_or_default()
        }
        other => serde_json::to_string(&super::IpcResponse::<()>::error(format!(
            "unknown request: {}",
            other
        )))
        .unwrap_or_default(),
    }
}
