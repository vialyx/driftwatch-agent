//! Stub platform implementations used on unsupported platforms and in tests.

use anyhow::Result;
use async_trait::async_trait;
use chrono::Utc;

use crate::scoring::{
    device_quantity::EnrolledDevice,
    geo_anchor::{GeoReading, GeoSource},
    network_risk::NetworkConnection,
};

use super::{DeviceRegistry, GeoProvider, NetworkMonitor};

/// A geo provider that always returns a fixed reading (useful for testing).
#[allow(dead_code)]
pub struct StubGeoProvider {
    pub reading: GeoReading,
}

impl StubGeoProvider {
    #[allow(dead_code)]
    pub fn new(lat: f64, lon: f64) -> Self {
        Self {
            reading: GeoReading {
                lat,
                lon,
                accuracy_meters: 10.0,
                source: GeoSource::Manual,
                timestamp: Utc::now(),
            },
        }
    }
}

#[async_trait]
impl GeoProvider for StubGeoProvider {
    async fn current_reading(&self) -> Result<GeoReading> {
        Ok(self.reading.clone())
    }
}

/// A network monitor that always returns an empty connection list.
#[allow(dead_code)]
pub struct StubNetworkMonitor;

#[async_trait]
impl NetworkMonitor for StubNetworkMonitor {
    async fn active_connections(&self) -> Result<Vec<NetworkConnection>> {
        Ok(vec![])
    }
}

/// A device registry that always returns an empty device list.
#[allow(dead_code)]
pub struct StubDeviceRegistry;

#[async_trait]
impl DeviceRegistry for StubDeviceRegistry {
    async fn enrolled_devices(&self) -> Result<Vec<EnrolledDevice>> {
        Ok(vec![])
    }
}
