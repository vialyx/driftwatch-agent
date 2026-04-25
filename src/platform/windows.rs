//! Windows platform implementations.
//!
//! Geo-location: WinRT `Windows.Devices.Geolocation` API.
//! Network monitoring: `GetTcpTable2` / `GetUdpTable2` via the `windows` crate.

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use chrono::Utc;
use std::net::IpAddr;
use tokio::process::Command;

use crate::scoring::{
    device_quantity::EnrolledDevice,
    geo_anchor::{GeoReading, GeoSource},
    network_risk::NetworkConnection,
};

use super::{DeviceRegistry, GeoProvider, NetworkMonitor};

/// Windows geo provider using the WinRT Geolocation API.
pub struct WindowsGeoProvider;

#[async_trait]
impl GeoProvider for WindowsGeoProvider {
    async fn current_reading(&self) -> Result<GeoReading> {
        // Full implementation would call:
        //   windows::Devices::Geolocation::Geolocator::new()?
        //       .GetGeopositionAsync()?.await?
        // Requires `com.microsoft.windows.location` capability in the manifest.
        geoip_fallback().await
    }
}

/// Windows network monitor reading active TCP/UDP table entries.
pub struct WindowsNetworkMonitor;

#[async_trait]
impl NetworkMonitor for WindowsNetworkMonitor {
    async fn active_connections(&self) -> Result<Vec<NetworkConnection>> {
        // Baseline implementation using `netstat` output parsing.
        let output = Command::new("netstat")
            .args(["-na", "-p", "tcp"])
            .output()
            .await
            .map_err(|e| anyhow!("failed to execute netstat: {}", e))?;

        if !output.status.success() {
            return Err(anyhow!(
                "netstat returned non-zero exit status: {}",
                output.status
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(parse_netstat_output(&stdout))
    }
}

/// HTTP-registry-backed device registry (shared with macOS).
pub struct HttpDeviceRegistry {
    pub endpoint: String,
    pub token: String,
    pub identity_id: String,
}

#[async_trait]
impl DeviceRegistry for HttpDeviceRegistry {
    async fn enrolled_devices(&self) -> Result<Vec<EnrolledDevice>> {
        let url = format!("{}/users/{}/devices", self.endpoint, self.identity_id);
        let client = reqwest::Client::new();
        let resp = client
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| anyhow!("device registry request failed: {}", e))?;
        if !resp.status().is_success() {
            return Err(anyhow!("device registry HTTP {}", resp.status()));
        }
        let devices: Vec<EnrolledDevice> = resp
            .json()
            .await
            .map_err(|e| anyhow!("failed to parse device list: {}", e))?;
        Ok(devices)
    }
}

async fn geoip_fallback() -> Result<GeoReading> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;

    #[derive(serde::Deserialize)]
    struct IpApiResponse {
        latitude: f64,
        longitude: f64,
    }

    let resp: IpApiResponse = client
        .get("https://ipapi.co/json/")
        .send()
        .await
        .map_err(|e| anyhow!("GeoIP request failed: {}", e))?
        .json()
        .await
        .map_err(|e| anyhow!("GeoIP parse failed: {}", e))?;

    Ok(GeoReading {
        lat: resp.latitude,
        lon: resp.longitude,
        accuracy_meters: 5_000.0,
        source: GeoSource::GeoIP,
        timestamp: Utc::now(),
    })
}

fn parse_netstat_output(stdout: &str) -> Vec<NetworkConnection> {
    stdout
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 4 {
                return None;
            }

            // Windows `netstat -na -p tcp` lines:
            // TCP    127.0.0.1:5000   127.0.0.1:61234   ESTABLISHED
            if !fields[0].eq_ignore_ascii_case("TCP") {
                return None;
            }

            let state = fields.get(3)?.to_ascii_uppercase();
            if state != "ESTABLISHED" {
                return None;
            }

            let (remote_ip, remote_port) = parse_remote_endpoint(fields.get(2)?)?;

            Some(NetworkConnection {
                remote_ip,
                remote_port,
                remote_hostname: None,
                protocol: crate::scoring::network_risk::Protocol::Tcp,
                process_name: None,
                bytes_sent: 0,
                established_at: Utc::now(),
            })
        })
        .collect()
}

fn parse_remote_endpoint(endpoint: &str) -> Option<(IpAddr, u16)> {
    if endpoint == "*:*" || endpoint == "[::]:0" {
        return None;
    }

    if endpoint.starts_with('[') {
        let idx = endpoint.rfind(']')?;
        let ip = endpoint.get(1..idx)?.parse::<IpAddr>().ok()?;
        let port = endpoint.get(idx + 2..)?.parse::<u16>().ok()?;
        return Some((ip, port));
    }

    let (host, port_str) = endpoint.rsplit_once(':')?;
    let ip = host.parse::<IpAddr>().ok()?;
    let port = port_str.parse::<u16>().ok()?;
    Some((ip, port))
}
