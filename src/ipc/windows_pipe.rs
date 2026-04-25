//! Windows Named Pipe IPC server.
//!
//! Listens on `\\.\pipe\riskagent`.  Each connection receives a
//! newline-delimited JSON request and gets back a newline-delimited JSON
//! response.
//!
//! Uses `tokio::net::windows::named_pipe` (available in tokio 1.x when
//! targeting Windows).

use std::sync::Arc;

use anyhow::Result;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{error, info};

use super::IpcState;
use crate::scoring::RiskScore;

/// Named pipe path used on Windows.
pub const PIPE_NAME: &str = r"\\.\pipe\riskagent";

/// Serve IPC requests on the Windows named pipe until the process exits.
pub async fn serve(state: Arc<IpcState>) -> Result<()> {
    use tokio::net::windows::named_pipe::ServerOptions;

    info!("IPC listening on {}", PIPE_NAME);

    loop {
        let server = ServerOptions::new()
            .first_pipe_instance(false)
            .create(PIPE_NAME)
            .map_err(|e| anyhow::anyhow!("failed to create named pipe: {}", e))?;

        // Wait for a client to connect.
        server
            .connect()
            .await
            .map_err(|e| anyhow::anyhow!("named pipe connect failed: {}", e))?;

        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(server, state).await {
                error!("Named pipe connection error: {}", e);
            }
        });
    }
}

async fn handle_connection(
    stream: tokio::net::windows::named_pipe::NamedPipeServer,
    state: Arc<IpcState>,
) -> Result<()> {
    let (reader, mut writer) = tokio::io::split(stream);
    let mut lines = BufReader::new(reader).lines();

    while let Some(line) = lines.next_line().await? {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        let response = dispatch_request(&line, &state).await;
        writer.write_all(response.as_bytes()).await?;
        writer.write_all(b"\n").await?;
    }

    Ok(())
}

async fn dispatch_request(request: &str, state: &IpcState) -> String {
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
