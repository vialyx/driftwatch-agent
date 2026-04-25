use anyhow::Result;

use crate::scoring::RiskScore;

pub mod unix;
#[cfg(target_os = "windows")]
pub mod windows_pipe;

/// IPC request type.
#[allow(dead_code)]
#[derive(Debug, serde::Deserialize)]
#[serde(tag = "method")]
pub enum IpcRequest {
    #[serde(rename = "GET /risk/current")]
    GetCurrent,
    #[serde(rename = "GET /risk/history")]
    GetHistory { n: usize },
    #[serde(rename = "POST /risk/force-refresh")]
    ForceRefresh,
}

/// IPC response envelope.
#[derive(Debug, serde::Serialize)]
pub struct IpcResponse<T: serde::Serialize> {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl<T: serde::Serialize> IpcResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            ok: true,
            data: Some(data),
            error: None,
        }
    }
    pub fn error(msg: impl Into<String>) -> IpcResponse<()> {
        IpcResponse {
            ok: false,
            data: None,
            error: Some(msg.into()),
        }
    }
}

/// Shared state available to IPC handler tasks.
pub struct IpcState {
    /// Latest computed risk score.
    pub latest_score: tokio::sync::RwLock<Option<RiskScore>>,
    /// Signal to trigger an immediate recompute.
    pub force_refresh_tx: tokio::sync::watch::Sender<()>,
}

impl IpcState {
    pub fn new(force_refresh_tx: tokio::sync::watch::Sender<()>) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            latest_score: tokio::sync::RwLock::new(None),
            force_refresh_tx,
        })
    }
}

/// Start the platform-appropriate IPC server.
pub async fn serve(state: std::sync::Arc<IpcState>) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        windows_pipe::serve(state).await
    }
    #[cfg(not(target_os = "windows"))]
    {
        unix::serve(state).await
    }
}
