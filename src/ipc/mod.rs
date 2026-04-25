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
    Ok(serde_json::from_str::<AuthenticatedIpcRequest>(
        line.trim(),
    )?)
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
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_response_success() {
        let resp = IpcResponse::success("test_data");
        assert!(resp.ok);
        assert_eq!(resp.data, Some("test_data"));
        assert_eq!(resp.error, None);
    }

    #[test]
    fn test_response_error() {
        let resp = IpcResponse::<String>::error("error message");
        assert!(!resp.ok);
        assert_eq!(resp.data, None);
        assert_eq!(resp.error, Some("error message".to_string()));
    }

    #[test]
    fn test_parse_get_current_request() {
        let json = r#"{"token": "auth_token", "method": "GET /risk/current"}"#;
        let req = parse_authenticated_request(json);
        assert!(req.is_ok());
        let req = req.unwrap();
        assert_eq!(req.token, "auth_token");
        match req.request {
            IpcRequest::GetCurrent => {}
            _ => panic!("Expected GetCurrent"),
        }
    }

    #[test]
    fn test_parse_get_history_request() {
        let json = r#"{"token": "auth_token", "method": "GET /risk/history", "n": 10}"#;
        let req = parse_authenticated_request(json);
        assert!(req.is_ok());
        let req = req.unwrap();
        assert_eq!(req.token, "auth_token");
        match req.request {
            IpcRequest::GetHistory { n } => assert_eq!(n, 10),
            _ => panic!("Expected GetHistory"),
        }
    }

    #[test]
    fn test_parse_force_refresh_request() {
        let json = r#"{"token": "auth_token", "method": "POST /risk/force-refresh"}"#;
        let req = parse_authenticated_request(json);
        assert!(req.is_ok());
        let req = req.unwrap();
        assert_eq!(req.token, "auth_token");
        match req.request {
            IpcRequest::ForceRefresh => {}
            _ => panic!("Expected ForceRefresh"),
        }
    }

    #[test]
    fn test_constant_time_eq_equal_strings() {
        assert!(constant_time_eq("token123", "token123"));
    }

    #[test]
    fn test_constant_time_eq_different_strings() {
        assert!(!constant_time_eq("token123", "token456"));
    }

    #[test]
    fn test_constant_time_eq_different_lengths() {
        assert!(!constant_time_eq("token123", "token"));
    }

    #[test]
    fn test_constant_time_eq_empty_strings() {
        assert!(constant_time_eq("", ""));
    }

    #[test]
    fn test_constant_time_eq_empty_vs_nonempty() {
        assert!(!constant_time_eq("", "token"));
    }

    #[tokio::test]
    async fn test_ipc_state_creation() {
        let (tx, _rx) = tokio::sync::watch::channel(());
        let state = IpcState::new(tx, "test_token".to_string(), 100);
        assert_eq!(state.auth_token, "test_token");
        assert_eq!(state.history_limit, 100);
    }

    #[tokio::test]
    async fn test_ipc_state_push_score() {
        let (tx, _rx) = tokio::sync::watch::channel(());
        let state = IpcState::new(tx, "test_token".to_string(), 10);

        let score = crate::scoring::RiskScore {
            composite: 0.5,
            geo_anchor: 0.4,
            network_destination: 0.5,
            device_quantity: 0.6,
            level: crate::scoring::RiskLevel::Medium,
            computed_at: Utc::now(),
            signals_version: "0.1.0".to_string(),
        };

        state.push_score(score.clone()).await;

        let latest = state.latest_score.read().await;
        assert!(latest.is_some());
        assert_eq!(latest.as_ref().unwrap().composite, 0.5);
    }

    #[tokio::test]
    async fn test_ipc_state_history_limit() {
        let (tx, _rx) = tokio::sync::watch::channel(());
        let state = IpcState::new(tx, "test_token".to_string(), 3);

        for i in 0..5 {
            let score = crate::scoring::RiskScore {
                composite: i as f32 * 0.1,
                geo_anchor: 0.0,
                network_destination: 0.0,
                device_quantity: 0.0,
                level: crate::scoring::RiskLevel::Low,
                computed_at: Utc::now(),
                signals_version: "0.1.0".to_string(),
            };
            state.push_score(score).await;
        }

        let history = state.history.read().await;
        assert!(history.len() <= 3);
    }

    #[test]
    fn test_invalid_json_request() {
        let json = r#"{"invalid": "json"}"#;
        let req = parse_authenticated_request(json);
        assert!(req.is_err());
    }
}
