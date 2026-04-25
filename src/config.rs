use anyhow::{anyhow, Result};
use config::{Config, Environment, File};
use serde::Deserialize;

/// Top-level agent configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct AgentConfig {
    pub agent: AgentSection,
    pub geo_anchor: GeoAnchorConfig,
    pub network_risk: NetworkRiskConfig,
    pub device_quantity: DeviceQuantityConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AgentSection {
    pub poll_interval_secs: u64,
    pub log_level: String,
    pub telemetry_endpoint: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GeoAnchorConfig {
    #[allow(dead_code)]
    pub anchor_radius_meters: f64,
    pub trusted_anchors: Vec<Anchor>,
    pub weight: f32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Anchor {
    #[allow(dead_code)]
    pub name: String,
    pub lat: f64,
    pub lon: f64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NetworkRiskConfig {
    pub threat_feed_url: String,
    pub refresh_interval_secs: u64,
    pub weight: f32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DeviceQuantityConfig {
    pub max_trusted_devices: usize,
    pub identity_registry_url: String,
    pub weight: f32,
}

impl AgentConfig {
    /// Load configuration from the default TOML file and optional environment overrides.
    pub fn load() -> Result<Self> {
        let cfg = Config::builder()
            .add_source(File::with_name("config/default").required(true))
            .add_source(
                Environment::with_prefix("DRIFTWATCH")
                    .separator("__")
                    .try_parsing(true),
            )
            .build()?;

        let config: AgentConfig = cfg.try_deserialize()?;
        config.validate()?;
        Ok(config)
    }

    /// Validate that signal weights sum to 1.0 (within floating-point tolerance).
    pub fn validate(&self) -> Result<()> {
        let sum = self.geo_anchor.weight
            + self.network_risk.weight
            + self.device_quantity.weight;

        if (sum - 1.0_f32).abs() > 0.01 {
            return Err(anyhow!(
                "Signal weights must sum to 1.0, got {:.4} \
                 (geo={}, network={}, device={})",
                sum,
                self.geo_anchor.weight,
                self.network_risk.weight,
                self.device_quantity.weight,
            ));
        }

        if self.geo_anchor.trusted_anchors.is_empty() {
            return Err(anyhow!("At least one trusted geo anchor must be configured"));
        }

        Ok(())
    }

    /// Convenience: weights as a struct for the scoring engine.
    pub fn weights(&self) -> crate::scoring::Weights {
        crate::scoring::Weights {
            geo_anchor: self.geo_anchor.weight,
            network_destination: self.network_risk.weight,
            device_quantity: self.device_quantity.weight,
        }
    }
}
