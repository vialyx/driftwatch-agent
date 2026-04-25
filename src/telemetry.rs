//! Telemetry: sign and emit risk score events to the configured endpoint.
//!
//! Events are HMAC-SHA256 signed using a device-bound key.  Failed deliveries
//! are queued in a local SQLite ring buffer and retried with exponential
//! back-off (max 3 attempts).

use anyhow::{anyhow, Result};
use chrono::Utc;
use hmac::{Hmac, Mac};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::sync::Mutex;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::scoring::{geo_anchor::GeoSource, RiskScore};

type HmacSha256 = Hmac<Sha256>;

/// Full telemetry event emitted to the risk engine / SIEM.
#[derive(Debug, Serialize, Deserialize)]
pub struct RiskEvent {
    pub event_id: String,
    pub device_id: String,
    pub identity_id: String,
    pub risk: RiskEventRisk,
    pub signals_meta: SignalsMeta,
    pub computed_at: String,
    pub agent_version: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RiskEventRisk {
    pub composite: f32,
    pub level: String,
    pub geo_anchor: f32,
    pub network_destination: f32,
    pub device_quantity: f32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignalsMeta {
    pub geo_source: String,
    pub geo_accuracy_m: f32,
    pub active_connections: usize,
    pub malicious_connections: usize,
    pub enrolled_devices: usize,
}

/// Telemetry emitter.
pub struct TelemetryEmitter {
    endpoint: String,
    device_id: String,
    identity_id: String,
    signing_key: Vec<u8>,
    client: reqwest::Client,
    queue: Mutex<Connection>,
}

impl TelemetryEmitter {
    /// Create a new emitter backed by a SQLite ring-buffer queue.
    pub fn new(
        endpoint: String,
        device_id: String,
        identity_id: String,
        signing_key: Vec<u8>,
        db_path: &str,
    ) -> Result<Self> {
        let conn = Connection::open(db_path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS event_queue (
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                payload TEXT    NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                queued_at TEXT NOT NULL
            );
            -- Keep at most 1000 events to bound disk usage.
            CREATE TRIGGER IF NOT EXISTS queue_limit
            AFTER INSERT ON event_queue
            BEGIN
                DELETE FROM event_queue
                WHERE id IN (
                    SELECT id FROM event_queue
                    ORDER BY id DESC
                    LIMIT -1 OFFSET 1000
                );
            END;",
        )?;
        Ok(Self {
            endpoint,
            device_id,
            identity_id,
            signing_key,
            client: reqwest::Client::new(),
            queue: Mutex::new(conn),
        })
    }

    /// Build a `RiskEvent` from a `RiskScore` and optional signal metadata.
    pub fn build_event(
        &self,
        score: &RiskScore,
        geo_source: &GeoSource,
        geo_accuracy_m: f32,
        active_connections: usize,
        malicious_connections: usize,
        enrolled_devices: usize,
    ) -> RiskEvent {
        RiskEvent {
            event_id: Uuid::new_v4().to_string(),
            device_id: self.device_id.clone(),
            identity_id: self.identity_id.clone(),
            risk: RiskEventRisk {
                composite: score.composite,
                level: score.level.to_string(),
                geo_anchor: score.geo_anchor,
                network_destination: score.network_destination,
                device_quantity: score.device_quantity,
            },
            signals_meta: SignalsMeta {
                geo_source: format!("{:?}", geo_source),
                geo_accuracy_m,
                active_connections,
                malicious_connections,
                enrolled_devices,
            },
            computed_at: score.computed_at.to_rfc3339(),
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    /// Sign a JSON payload and return the hex-encoded HMAC-SHA256.
    pub fn sign(&self, payload: &str) -> String {
        let mut mac =
            HmacSha256::new_from_slice(&self.signing_key).expect("HMAC accepts any key length");
        mac.update(payload.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    /// Emit an event: attempt delivery, queue on failure.
    pub async fn emit(&self, event: &RiskEvent) -> Result<()> {
        let payload = serde_json::to_string(event)?;
        let signature = self.sign(&payload);

        match self.send_with_retry(&payload, &signature, 3).await {
            Ok(()) => {
                info!("Telemetry event {} delivered", event.event_id);
                Ok(())
            }
            Err(e) => {
                warn!(
                    "Telemetry delivery failed for event {}: {}. Queuing for retry.",
                    event.event_id, e
                );
                self.enqueue(&payload)?;
                Ok(())
            }
        }
    }

    /// Retry queued events that failed previously.
    pub async fn flush_queue(&self) {
        let rows: Vec<(i64, String)> = {
            let conn = self.queue.lock().expect("queue mutex poisoned");
            let mut stmt = match conn
                .prepare("SELECT id, payload FROM event_queue WHERE attempts < 3 ORDER BY id")
            {
                Ok(s) => s,
                Err(e) => {
                    error!("Failed to prepare queue flush query: {}", e);
                    return;
                }
            };
            let result: Vec<(i64, String)> =
                match stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?))) {
                    Ok(iter) => iter.filter_map(|r| r.ok()).collect(),
                    Err(e) => {
                        error!("Failed to query event queue: {}", e);
                        return;
                    }
                };
            result
        };

        for (id, payload) in rows {
            let sig = self.sign(&payload);
            match self.send_with_retry(&payload, &sig, 1).await {
                Ok(()) => {
                    let conn = self.queue.lock().expect("queue mutex poisoned");
                    if let Err(e) =
                        conn.execute("DELETE FROM event_queue WHERE id = ?1", params![id])
                    {
                        error!(
                            "Failed to delete queued event {} after successful send: {}",
                            id, e
                        );
                    }
                }
                Err(_) => {
                    let conn = self.queue.lock().expect("queue mutex poisoned");
                    if let Err(e) = conn.execute(
                        "UPDATE event_queue SET attempts = attempts + 1 WHERE id = ?1",
                        params![id],
                    ) {
                        error!(
                            "Failed to increment attempts for queued event {}: {}",
                            id, e
                        );
                    }
                }
            }
        }
    }

    async fn send_with_retry(
        &self,
        payload: &str,
        signature: &str,
        max_attempts: u32,
    ) -> Result<()> {
        let mut last_err = anyhow!("no attempts made");
        for attempt in 0..max_attempts {
            match self
                .client
                .post(&self.endpoint)
                .header("Content-Type", "application/json")
                .header("X-Signature-SHA256", signature)
                .body(payload.to_string())
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => return Ok(()),
                Ok(resp) => {
                    last_err = anyhow!("HTTP {}", resp.status());
                }
                Err(e) => {
                    last_err = anyhow!("{}", e);
                }
            }
            if attempt + 1 < max_attempts {
                let backoff = std::time::Duration::from_millis(500 * 2u64.pow(attempt));
                tokio::time::sleep(backoff).await;
            }
        }
        Err(last_err)
    }

    pub fn enqueue(&self, payload: &str) -> Result<()> {
        let conn = self.queue.lock().expect("queue mutex poisoned");
        conn.execute(
            "INSERT INTO event_queue (payload, queued_at) VALUES (?1, ?2)",
            params![payload, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_emitter() -> TelemetryEmitter {
        TelemetryEmitter::new(
            "http://localhost:1/events".to_string(),
            "device-test".to_string(),
            "user@test.com".to_string(),
            b"test-signing-key".to_vec(),
            ":memory:",
        )
        .unwrap()
    }

    #[test]
    fn sign_produces_hex_string() {
        let em = make_emitter();
        let sig = em.sign("hello world");
        assert_eq!(sig.len(), 64); // 32-byte HMAC = 64 hex chars
        assert!(sig.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn sign_is_deterministic() {
        let em = make_emitter();
        assert_eq!(em.sign("payload"), em.sign("payload"));
    }

    #[test]
    fn sign_differs_for_different_payload() {
        let em = make_emitter();
        assert_ne!(em.sign("a"), em.sign("b"));
    }

    #[test]
    fn enqueue_and_count() {
        let em = make_emitter();
        em.enqueue(r#"{"event_id":"1"}"#).unwrap();
        em.enqueue(r#"{"event_id":"2"}"#).unwrap();
        let conn = em.queue.lock().unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM event_queue", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 2);
    }
}
