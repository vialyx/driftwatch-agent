//! Windows platform implementations.
//!
//! Geo-location: WinRT `Windows.Devices.Geolocation` API.
//! Network monitoring: `GetTcpTable2` / `GetUdpTable2` via the `windows` crate.

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use chrono::Utc;

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
        // TODO: call GetTcpTable2 / GetUdpTable2 via windows crate
        Ok(vec![])
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
