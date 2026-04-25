//! macOS platform implementations.
//!
//! Geo-location: CoreLocation via `objc2-core-location`.
//! Network monitoring: reads active connections via stub (full NEPacketTunnel
//! requires a system extension entitlement that cannot be obtained at build time).

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use chrono::Utc;
use std::net::IpAddr;
use tokio::process::Command;
use tracing::warn;

use crate::scoring::{
    device_quantity::EnrolledDevice,
    geo_anchor::{GeoReading, GeoSource},
    network_risk::NetworkConnection,
};

use super::{DeviceRegistry, GeoProvider, NetworkMonitor};

/// macOS geo provider that queries CoreLocation.
///
/// Requires the `NSLocationWhenInUseUsageDescription` key in the app's Info.plist
/// and the `com.apple.security.personal-information.location` entitlement.
pub struct MacOsGeoProvider;

#[async_trait]
impl GeoProvider for MacOsGeoProvider {
    async fn current_reading(&self) -> Result<GeoReading> {
        match corelocation_reading().await {
            Ok(r) => Ok(r),
            Err(e) => {
                warn!("CoreLocation unavailable ({}), falling back to GeoIP", e);
                geoip_fallback().await
            }
        }
    }
}

/// macOS network monitor — stubs active connections for now.
/// Full implementation would use NEPacketTunnelProvider or poll `nettop`.
pub struct MacOsNetworkMonitor;

#[async_trait]
impl NetworkMonitor for MacOsNetworkMonitor {
    async fn active_connections(&self) -> Result<Vec<NetworkConnection>> {
        // Uses `netstat` parsing as a capability-free baseline.
        let output = Command::new("netstat")
            .args(["-an", "-p", "tcp"])
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

/// GeoIP fallback using the ip-api.com JSON endpoint (no key required).
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
        accuracy_meters: 5_000.0, // GeoIP is city-level at best
        source: GeoSource::GeoIP,
        timestamp: Utc::now(),
    })
}

/// Attempt to retrieve location from CoreLocation by invoking the system Swift runtime.
///
/// This avoids requiring a long-lived Objective-C delegate inside the Rust process while still
/// using the native CoreLocation framework.
async fn corelocation_reading() -> Result<GeoReading> {
    let swift_script = r#"
import Foundation
import CoreLocation

final class LocationDelegate: NSObject, CLLocationManagerDelegate {
    let semaphore = DispatchSemaphore(value: 0)
    var latitude: Double?
    var longitude: Double?
    var accuracy: Double?
    var errorMessage: String?

    func locationManager(_ manager: CLLocationManager, didUpdateLocations locations: [CLLocation]) {
        if let loc = locations.last {
            latitude = loc.coordinate.latitude
            longitude = loc.coordinate.longitude
            accuracy = loc.horizontalAccuracy
            semaphore.signal()
        }
    }

    func locationManager(_ manager: CLLocationManager, didFailWithError error: Error) {
        errorMessage = error.localizedDescription
        semaphore.signal()
    }
}

if !CLLocationManager.locationServicesEnabled() {
    fputs("location services disabled\n", stderr)
    exit(2)
}

let manager = CLLocationManager()
let delegate = LocationDelegate()
manager.delegate = delegate
manager.desiredAccuracy = kCLLocationAccuracyBest
manager.requestWhenInUseAuthorization()
manager.requestLocation()

let timeout = DispatchTime.now() + .seconds(8)
if delegate.semaphore.wait(timeout: timeout) == .success,
   let lat = delegate.latitude,
   let lon = delegate.longitude,
   let acc = delegate.accuracy {
    print("\(lat),\(lon),\(acc)")
} else {
    if let msg = delegate.errorMessage {
        fputs("\(msg)\n", stderr)
    } else {
        fputs("location timeout\n", stderr)
    }
    exit(3)
}
"#;

    let output = Command::new("swift")
        .args(["-e", swift_script])
        .output()
        .await
        .map_err(|e| anyhow!("failed to execute swift CoreLocation probe: {}", e))?;

    if !output.status.success() {
        return Err(anyhow!(
            "CoreLocation probe failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let (lat, lon, acc) = parse_csv_triplet(stdout.trim())?;

    Ok(GeoReading {
        lat,
        lon,
        accuracy_meters: acc.max(0.0),
        source: GeoSource::CoreLocation,
        timestamp: Utc::now(),
    })
}

fn parse_csv_triplet(s: &str) -> Result<(f64, f64, f32)> {
    let mut it = s.split(',').map(str::trim);
    let lat = it
        .next()
        .ok_or_else(|| anyhow!("missing latitude in CoreLocation output"))?
        .parse::<f64>()
        .map_err(|e| anyhow!("invalid latitude in CoreLocation output: {}", e))?;
    let lon = it
        .next()
        .ok_or_else(|| anyhow!("missing longitude in CoreLocation output"))?
        .parse::<f64>()
        .map_err(|e| anyhow!("invalid longitude in CoreLocation output: {}", e))?;
    let acc = it
        .next()
        .ok_or_else(|| anyhow!("missing accuracy in CoreLocation output"))?
        .parse::<f32>()
        .map_err(|e| anyhow!("invalid accuracy in CoreLocation output: {}", e))?;
    Ok((lat, lon, acc))
}

fn parse_netstat_output(stdout: &str) -> Vec<NetworkConnection> {
    stdout
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 6 {
                return None;
            }

            let state = fields.last()?.to_ascii_uppercase();
            if state != "ESTABLISHED" {
                return None;
            }

            let remote = fields.get(4)?;
            let (remote_ip, remote_port) = parse_remote_endpoint(remote)?;

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
    if endpoint == "*.*" {
        return None;
    }

    // IPv6 netstat format commonly uses `ip.port` and includes `::ffff:` mapped
    // addresses. Splitting from the right works for both v4 and v6 here.
    let (host, port_str) = endpoint.rsplit_once('.')?;
    let port = port_str.parse::<u16>().ok()?;
    let host = host.trim_start_matches("::ffff:");
    let ip = host.parse::<IpAddr>().ok()?;
    Some((ip, port))
}
