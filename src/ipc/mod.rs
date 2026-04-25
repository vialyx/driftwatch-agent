use anyhow::Result;
use std::collections::VecDeque;

use crate::scoring::RiskScore;

pub mod unix;
#[cfg(target_os = "windows")]
pub mod windows_pipe;

/// IPC request type.
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

/// Authenticated IPC envelope.
#[derive(Debug, serde::Deserialize)]
pub struct AuthenticatedIpcRequest {
    pub token: String,
    #[serde(flatten)]
    pub request: IpcRequest,
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
    /// In-memory rolling history of recently computed scores.
    pub history: tokio::sync::RwLock<VecDeque<RiskScore>>,
    /// Maximum number of historical scores retained in memory.
    pub history_limit: usize,
    /// Signal to trigger an immediate recompute.
    pub force_refresh_tx: tokio::sync::watch::Sender<()>,
    /// Static bearer token required for all IPC requests.
    pub auth_token: String,
}

impl IpcState {
    pub fn new(
        force_refresh_tx: tokio::sync::watch::Sender<()>,
        auth_token: String,
        history_limit: usize,
    ) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            latest_score: tokio::sync::RwLock::new(None),
            history: tokio::sync::RwLock::new(VecDeque::with_capacity(history_limit.max(1))),
            history_limit: history_limit.max(1),
            force_refresh_tx,
            auth_token,
        })
    }

    pub async fn push_score(&self, score: RiskScore) {
        {
            let mut latest = self.latest_score.write().await;
            *latest = Some(score.clone());
        }

        let mut history = self.history.write().await;
        history.push_back(score);
        while history.len() > self.history_limit {
            history.pop_front();
        }
    }
}

pub fn parse_authenticated_request(line: &str) -> Result<AuthenticatedIpcRequest> {
    Ok(serde_json::from_str::<AuthenticatedIpcRequest>(line.trim())?)
}

pub fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        diff |= x ^ y;
    }
    diff == 0
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
