use anyhow::Result;
use async_trait::async_trait;

use crate::scoring::{
    device_quantity::EnrolledDevice, geo_anchor::GeoReading, network_risk::NetworkConnection,
};

/// Abstraction over platform-specific geo-location providers.
#[async_trait]
pub trait GeoProvider: Send + Sync {
    async fn current_reading(&self) -> Result<GeoReading>;
}

/// Abstraction over platform-specific network monitors.
#[async_trait]
pub trait NetworkMonitor: Send + Sync {
    async fn active_connections(&self) -> Result<Vec<NetworkConnection>>;
}

/// Abstraction over identity device registries.
#[async_trait]
pub trait DeviceRegistry: Send + Sync {
    async fn enrolled_devices(&self) -> Result<Vec<EnrolledDevice>>;
}

// Pull in the platform-specific implementations so they are compiled
// and their types are accessible without having to name the module explicitly.
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "windows")]
pub mod windows;

// Expose a fallback stub on any platform not yet fully implemented
// (useful for CI that runs on the build host).
pub mod stub;
