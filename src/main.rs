//! driftwatch-agent — cross-platform device risk scoring daemon.
//!
//! Computes a composite Device Risk Score from three real-time signals:
//!   1. Workspace Geo-Anchor deviation
//!   2. Network Destination Risk
//!   3. Device Quantity
//!
//! Exposes a local IPC interface for policy enforcement consumers and emits
//! signed events to a central risk engine / SIEM.

use std::sync::Arc;
use std::time::Duration;
use std::{path::PathBuf, str::FromStr};

use anyhow::{anyhow, Context, Result};
use tracing::{error, info, warn};

mod config;
mod ipc;
mod keychain;
mod platform;
mod scoring;
mod telemetry;

use config::AgentConfig;
use ipc::IpcState;
use platform::{DeviceRegistry, GeoProvider, NetworkMonitor};
use scoring::{
    compute_composite,
    device_quantity::score_device_quantity,
    geo_anchor::score_geo_anchor,
    network_risk::{score_network_risk, ThreatFeed},
};

#[tokio::main]
async fn main() -> Result<()> {
    // Load configuration.
    let cfg = AgentConfig::load().unwrap_or_else(|e| {
        eprintln!("Failed to load configuration: {}", e);
        std::process::exit(1);
    });

    // Initialise logging.
    let log_level: tracing::Level = cfg.agent.log_level.parse().unwrap_or(tracing::Level::INFO);
    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .with_target(false)
        .init();

    info!(
        "driftwatch-agent {} starting (poll interval: {}s)",
        env!("CARGO_PKG_VERSION"),
        cfg.agent.poll_interval_secs
    );

    // Build platform-appropriate providers.
    let geo_provider: Arc<dyn GeoProvider> = build_geo_provider();
    let network_monitor: Arc<dyn NetworkMonitor> = build_network_monitor();
    let identity_id = get_identity_id().unwrap_or_else(|e| {
        error!("Failed to resolve identity ID: {}", e);
        std::process::exit(1);
    });

    let device_registry: Arc<dyn DeviceRegistry> = build_device_registry(&cfg, identity_id.clone());

    // IPC state shared between the polling loop and the IPC server.
    let (force_refresh_tx, mut force_refresh_rx) = tokio::sync::watch::channel(());
    let ipc_token = get_or_create_ipc_token().unwrap_or_else(|e| {
        error!("Failed to initialize IPC auth token: {}", e);
        std::process::exit(1);
    });
    let ipc_state = IpcState::new(force_refresh_tx, ipc_token, 1000);

    // Retrieve (or generate) the HMAC signing key from the platform keychain.
    let signing_key = get_or_create_signing_key();

    // Telemetry emitter with local SQLite queue.
    let queue_db_path = state_dir().join("driftwatch_queue.db");
    if let Some(parent) = queue_db_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let emitter = Arc::new(
        telemetry::TelemetryEmitter::new(
            cfg.agent.telemetry_endpoint.clone(),
            device_fingerprint(),
            identity_id.clone(),
            signing_key,
            queue_db_path.to_string_lossy().as_ref(),
        )
        .unwrap_or_else(|e| {
            error!("Failed to initialise telemetry emitter: {}", e);
            std::process::exit(1);
        }),
    );

    // Spawn the IPC server.
    let ipc_state_clone = ipc_state.clone();
    tokio::spawn(async move {
        if let Err(e) = ipc::serve(ipc_state_clone).await {
            error!("IPC server error: {}", e);
        }
    });

    // Main polling loop.
    let mut threat_feed = ThreatFeed::default();
    let mut feed_refresh_counter = 0u64;
    let feed_refresh_every =
        cfg.network_risk.refresh_interval_secs / cfg.agent.poll_interval_secs.max(1);

    let weights = cfg.weights();

    loop {
        // Refresh threat feed on schedule.
        if feed_refresh_counter == 0 {
            match refresh_threat_feed(&cfg.network_risk.threat_feed_url).await {
                Ok(feed) => {
                    threat_feed = feed;
                    info!("Threat feed refreshed");
                }
                Err(e) => {
                    warn!("Failed to refresh threat feed: {}", e);
                }
            }
        }
        feed_refresh_counter = (feed_refresh_counter + 1) % feed_refresh_every.max(1);

        // --- Collect signals ---
        let geo_reading = match geo_provider.current_reading().await {
            Ok(r) => r,
            Err(e) => {
                warn!("Geo reading failed: {}", e);
                // Continue with remaining signals; geo score will default to 1.0
                make_fallback_geo_reading()
            }
        };

        let connections = match network_monitor.active_connections().await {
            Ok(c) => c,
            Err(e) => {
                warn!("Network monitor failed: {}", e);
                vec![]
            }
        };

        let devices = match device_registry.enrolled_devices().await {
            Ok(d) => d,
            Err(e) => {
                warn!("Device registry failed: {}", e);
                vec![]
            }
        };

        // --- Score signals ---
        let geo_score = score_geo_anchor(&geo_reading, &cfg.geo_anchor.trusted_anchors);
        let network_score = score_network_risk(&connections, &threat_feed);
        let device_score = score_device_quantity(&devices, cfg.device_quantity.max_trusted_devices);

        // --- Compute composite ---
        let risk_score = compute_composite(geo_score, network_score, device_score, &weights);

        info!(
            "Risk score: composite={:.3} level={} (geo={:.3}, net={:.3}, dev={:.3})",
            risk_score.composite, risk_score.level, geo_score, network_score, device_score
        );

        // Count malicious connections for telemetry meta.
        let malicious = connections
            .iter()
            .filter(|c| {
                matches!(
                    threat_feed.classify(&c.remote_ip, c.remote_hostname.as_deref()),
                    scoring::network_risk::DestinationRisk::Malicious
                )
            })
            .count();

        // Publish latest score to IPC state.
        ipc_state.push_score(risk_score.clone()).await;

        // Build and emit the telemetry event.
        let event = emitter.build_event(
            &risk_score,
            &geo_reading.source,
            geo_reading.accuracy_meters,
            connections.len(),
            malicious,
            devices.len(),
        );
        if let Err(e) = emitter.emit(&event).await {
            warn!("Telemetry emission error: {}", e);
        }

        // Flush any queued events that previously failed.
        emitter.flush_queue().await;

        // Wait for the poll interval or a force-refresh signal.
        let poll = Duration::from_secs(cfg.agent.poll_interval_secs);
        tokio::select! {
            _ = tokio::time::sleep(poll) => {}
            _ = force_refresh_rx.changed() => {
                info!("Force refresh triggered via IPC");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Platform provider factories
// ---------------------------------------------------------------------------

fn build_geo_provider() -> Arc<dyn GeoProvider> {
    #[cfg(target_os = "macos")]
    {
        Arc::new(platform::macos::MacOsGeoProvider)
    }
    #[cfg(target_os = "windows")]
    {
        Arc::new(platform::windows::WindowsGeoProvider)
    }
    #[cfg(target_os = "linux")]
    {
        Arc::new(platform::linux::LinuxGeoProvider)
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        Arc::new(platform::stub::StubGeoProvider::new(0.0, 0.0))
    }
}

fn build_network_monitor() -> Arc<dyn NetworkMonitor> {
    #[cfg(target_os = "macos")]
    {
        Arc::new(platform::macos::MacOsNetworkMonitor)
    }
    #[cfg(target_os = "windows")]
    {
        Arc::new(platform::windows::WindowsNetworkMonitor)
    }
    #[cfg(target_os = "linux")]
    {
        Arc::new(platform::linux::LinuxNetworkMonitor)
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        Arc::new(platform::stub::StubNetworkMonitor)
    }
}

fn build_device_registry(cfg: &AgentConfig, identity_id: String) -> Arc<dyn DeviceRegistry> {
    // Use the HTTP registry; authentication token is fetched from the keychain.
    let token = keychain::get_secret("driftwatch", "registry-token")
        .map(|b| String::from_utf8_lossy(&b).to_string())
        .unwrap_or_default();

    #[cfg(target_os = "macos")]
    {
        Arc::new(platform::macos::HttpDeviceRegistry {
            endpoint: cfg.device_quantity.identity_registry_url.clone(),
            token,
            identity_id: identity_id.clone(),
        })
    }
    #[cfg(target_os = "windows")]
    {
        Arc::new(platform::windows::HttpDeviceRegistry {
            endpoint: cfg.device_quantity.identity_registry_url.clone(),
            token,
            identity_id: identity_id.clone(),
        })
    }
    #[cfg(target_os = "linux")]
    {
        Arc::new(platform::linux::HttpDeviceRegistry {
            endpoint: cfg.device_quantity.identity_registry_url.clone(),
            token,
            identity_id: identity_id.clone(),
        })
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        Arc::new(platform::stub::StubDeviceRegistry)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Return a stable device fingerprint, generating one on first run.
fn device_fingerprint() -> String {
    keychain::get_secret("driftwatch", "device-id")
        .and_then(|b| String::from_utf8(b).map_err(|e| anyhow::anyhow!("{}", e)))
        .unwrap_or_else(|_| {
            let id = uuid::Uuid::new_v4().to_string();
            let _ = keychain::set_secret("driftwatch", "device-id", id.as_bytes());
            id
        })
}

/// Return the authenticated identity ID from env/keychain.
///
/// Priority:
/// 1. `DRIFTWATCH_IDENTITY_ID` (and persist to keychain)
/// 2. previously persisted keychain value
fn get_identity_id() -> Result<String> {
    if let Ok(from_env) = std::env::var("DRIFTWATCH_IDENTITY_ID") {
        let trimmed = from_env.trim();
        if !trimmed.is_empty() {
            let _ = keychain::set_secret("driftwatch", "identity-id", trimmed.as_bytes());
            return Ok(trimmed.to_string());
        }
    }

    let from_keychain = keychain::get_secret("driftwatch", "identity-id")
        .context("identity id not found in keychain")?;
    let id = String::from_utf8(from_keychain)
        .map_err(|e| anyhow!("identity id in keychain is not valid UTF-8: {}", e))?;
    if id.trim().is_empty() {
        return Err(anyhow!("identity id is empty"));
    }
    Ok(id)
}

/// Generate cryptographically random bytes for the signing key using the OS CSPRNG.
///
/// This path only runs once on first start when the keychain is unavailable.
/// The generated key is immediately stored in the keychain for subsequent runs.
fn get_or_create_signing_key() -> Vec<u8> {
    keychain::get_secret("driftwatch", "signing-key").unwrap_or_else(|_| {
        let mut key = vec![0u8; 32];
        if let Err(e) = getrandom::getrandom(&mut key) {
            panic!("OS CSPRNG unavailable: {}", e);
        }
        let _ = keychain::set_secret("driftwatch", "signing-key", &key);
        key
    })
}

/// Return or create a random token used to authenticate local IPC requests.
fn get_or_create_ipc_token() -> Result<String> {
    if let Ok(bytes) = keychain::get_secret("driftwatch", "ipc-token") {
        let token = String::from_utf8(bytes)
            .map_err(|e| anyhow!("IPC token in keychain is not valid UTF-8: {}", e))?;
        if !token.trim().is_empty() {
            return Ok(token);
        }
    }

    let mut raw = [0u8; 32];
    getrandom::getrandom(&mut raw)
        .map_err(|e| anyhow!("OS CSPRNG unavailable for IPC token: {}", e))?;
    let token = hex::encode(raw);
    keychain::set_secret("driftwatch", "ipc-token", token.as_bytes())?;
    Ok(token)
}

fn state_dir() -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        if let Ok(path) = std::env::var("DRIFTWATCH_STATE_DIR") {
            return PathBuf::from(path);
        }
        return PathBuf::from("/var/lib/driftwatch-agent");
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(path) = std::env::var("DRIFTWATCH_STATE_DIR") {
            return PathBuf::from(path);
        }
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from_str(&home)
                .unwrap_or_else(|_| PathBuf::from("."))
                .join("Library/Application Support/driftwatch-agent");
        }
        PathBuf::from("./driftwatch-agent")
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(path) = std::env::var("DRIFTWATCH_STATE_DIR") {
            return PathBuf::from(path);
        }
        if let Ok(program_data) = std::env::var("PROGRAMDATA") {
            return PathBuf::from(program_data).join("Driftwatch/Agent");
        }
        return PathBuf::from("C:/ProgramData/Driftwatch/Agent");
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    PathBuf::from("./driftwatch-agent")
}

/// Return a fallback geo reading (max risk) when the provider fails.
fn make_fallback_geo_reading() -> scoring::geo_anchor::GeoReading {
    scoring::geo_anchor::GeoReading {
        lat: 0.0,
        lon: 0.0,
        accuracy_meters: f32::MAX,
        source: scoring::geo_anchor::GeoSource::Manual,
        timestamp: chrono::Utc::now(),
    }
}

/// Refresh the threat feed from the configured URL.
async fn refresh_threat_feed(url: &str) -> Result<ThreatFeed> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    let indicators: Vec<scoring::network_risk::Indicator> =
        client.get(url).send().await?.json().await?;

    Ok(ThreatFeed::from_indicators(indicators))
}
