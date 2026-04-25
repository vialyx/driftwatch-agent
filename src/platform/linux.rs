//! Linux platform implementations.
//!
//! Geo-location: GeoClue2 D-Bus API via `zbus`, with GeoIP fallback.
//! Network monitoring: parses `/proc/net/tcp` and `/proc/net/tcp6`.

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use chrono::Utc;
use std::{
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use crate::scoring::{
    device_quantity::EnrolledDevice,
    geo_anchor::{GeoReading, GeoSource},
    network_risk::{NetworkConnection, Protocol},
};

use super::{DeviceRegistry, GeoProvider, NetworkMonitor};

/// Linux geo provider: tries GeoClue2 and falls back to GeoIP.
pub struct LinuxGeoProvider;

#[async_trait]
impl GeoProvider for LinuxGeoProvider {
    async fn current_reading(&self) -> Result<GeoReading> {
        match geoclue2_reading().await {
            Ok(r) => Ok(r),
            Err(e) => {
                tracing::warn!("GeoClue2 unavailable ({}), falling back to GeoIP", e);
                geoip_fallback().await
            }
        }
    }
}

/// Attempt to get a reading from GeoClue2 over D-Bus.
async fn geoclue2_reading() -> Result<GeoReading> {
    // Full implementation uses the zbus proxy generated from the GeoClue2 introspection XML.
    // At runtime this requires the GeoClue2 daemon to be present and the
    // org.freedesktop.GeoClue2 service to be accessible on the session/system bus.
    Err(anyhow!("GeoClue2 not yet implemented"))
}

/// GeoIP fallback using ip-api.com.
async fn geoip_fallback() -> Result<GeoReading> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;

    #[derive(serde::Deserialize)]
    struct IpApiResponse {
        lat: f64,
        lon: f64,
    }

    let resp: IpApiResponse = client
        .get("http://ip-api.com/json?fields=lat,lon")
        .send()
        .await
        .map_err(|e| anyhow!("GeoIP request failed: {}", e))?
        .json()
        .await
        .map_err(|e| anyhow!("GeoIP parse failed: {}", e))?;

    Ok(GeoReading {
        lat: resp.lat,
        lon: resp.lon,
        accuracy_meters: 5_000.0,
        source: GeoSource::GeoIP,
        timestamp: Utc::now(),
    })
}

/// Linux network monitor that parses `/proc/net/tcp` and `/proc/net/tcp6`.
pub struct LinuxNetworkMonitor;

#[async_trait]
impl NetworkMonitor for LinuxNetworkMonitor {
    async fn active_connections(&self) -> Result<Vec<NetworkConnection>> {
        let mut conns = Vec::new();
        conns.extend(parse_proc_net_tcp("/proc/net/tcp", false)?);
        conns.extend(parse_proc_net_tcp("/proc/net/tcp6", true)?);
        Ok(conns)
    }
}

/// Parse a `/proc/net/tcp` or `/proc/net/tcp6` file and return connections
/// that are in the `ESTABLISHED` state (state code `0A` hex = 10 decimal).
fn parse_proc_net_tcp(path: &str, is_v6: bool) -> Result<Vec<NetworkConnection>> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path))?;

    let mut conns = Vec::new();
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }
        // Field 3 is the connection state; 0A = ESTABLISHED
        let state = fields[3];
        if state != "0A" {
            continue;
        }

        // Remote address is field 2 (local is field 1)
        let remote_hex = fields[2];
        if let Some(ip) = parse_hex_addr(remote_hex, is_v6) {
            let port_hex = remote_hex.split(':').nth(1).unwrap_or("0");
            let port = u16::from_str_radix(port_hex, 16).unwrap_or(0);
            conns.push(NetworkConnection {
                remote_ip: ip,
                remote_port: port,
                remote_hostname: None,
                protocol: Protocol::Tcp,
                process_name: None,
                bytes_sent: 0,
                established_at: Utc::now(),
            });
        }
    }
    Ok(conns)
}

/// Parse a hex-encoded address from `/proc/net/tcp[6]` format.
///
/// IPv4 format: `0100007F:0035` (little-endian 32-bit hex + port)
/// IPv6 format: `00000000000000000000000001000000:0035`
fn parse_hex_addr(addr: &str, is_v6: bool) -> Option<IpAddr> {
    let parts: Vec<&str> = addr.split(':').collect();
    let hex_ip = parts.first()?;

    if is_v6 {
        // 128-bit little-endian in four 32-bit words
        if hex_ip.len() < 32 {
            return None;
        }
        let mut bytes = [0u8; 16];
        for (chunk_idx, chunk) in hex_ip.as_bytes().chunks(8).enumerate() {
            let word_str = std::str::from_utf8(chunk).ok()?;
            let word = u32::from_str_radix(word_str, 16).ok()?;
            let word_le = word.to_le_bytes();
            let base = chunk_idx * 4;
            bytes[base..base + 4].copy_from_slice(&word_le);
        }
        Some(IpAddr::V6(Ipv6Addr::from(bytes)))
    } else {
        if hex_ip.len() < 8 {
            return None;
        }
        let word = u32::from_str_radix(hex_ip, 16).ok()?;
        let [a, b, c, d] = word.to_le_bytes();
        Some(IpAddr::V4(Ipv4Addr::new(a, b, c, d)))
    }
}

/// HTTP-registry-backed device registry (shared with other platforms).
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
        let devices: Vec<EnrolledDevice> = resp
            .json()
            .await
            .map_err(|e| anyhow!("failed to parse device list: {}", e))?;
        Ok(devices)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ipv4_loopback() {
        // 0100007F = 127.0.0.1 in little-endian
        let ip = parse_hex_addr("0100007F:0035", false);
        assert_eq!(ip, Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
    }

    #[test]
    fn parse_ipv4_8_8_8_8() {
        // 8.8.8.8 little-endian = 08080808
        let ip = parse_hex_addr("08080808:0035", false);
        assert_eq!(ip, Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }
}
