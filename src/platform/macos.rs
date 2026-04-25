//! macOS platform implementations.
//!
//! Geo-location: CoreLocation via `objc2-core-location`.
//! Network monitoring: reads active connections via stub (full NEPacketTunnel
//! requires a system extension entitlement that cannot be obtained at build time).

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use chrono::Utc;

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
        // In a production binary this would drive the CoreLocation manager via
        // objc2-core-location FFI.  For the initial implementation we return a
        // GeoIP fallback so the agent can still operate without a location
        // entitlement in development builds.
        geoip_fallback().await
    }
}

/// macOS network monitor — stubs active connections for now.
/// Full implementation would use NEPacketTunnelProvider or poll `nettop`.
pub struct MacOsNetworkMonitor;

#[async_trait]
impl NetworkMonitor for MacOsNetworkMonitor {
    async fn active_connections(&self) -> Result<Vec<NetworkConnection>> {
        // TODO: implement via NEPacketTunnelProvider / system extension
        Ok(vec![])
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

/// GeoIP fallback using the ip-api.com JSON endpoint (no key required).
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
        accuracy_meters: 5_000.0, // GeoIP is city-level at best
        source: GeoSource::GeoIP,
        timestamp: Utc::now(),
    })
}
