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
        let sum = self.geo_anchor.weight + self.network_risk.weight + self.device_quantity.weight;

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
            return Err(anyhow!(
                "At least one trusted geo anchor must be configured"
            ));
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

#[cfg(test)]
mod tests {
    use super::*;

    fn create_valid_config() -> AgentConfig {
        AgentConfig {
            agent: AgentSection {
                poll_interval_secs: 60,
                log_level: "INFO".to_string(),
                telemetry_endpoint: "https://example.com/telemetry".to_string(),
            },
            geo_anchor: GeoAnchorConfig {
                anchor_radius_meters: 100.0,
                trusted_anchors: vec![Anchor {
                    name: "HQ".to_string(),
                    lat: 39.6138,
                    lon: -105.0166,
                }],
                weight: 0.40,
            },
            network_risk: NetworkRiskConfig {
                threat_feed_url: "https://example.com/feed".to_string(),
                refresh_interval_secs: 3600,
                weight: 0.35,
            },
            device_quantity: DeviceQuantityConfig {
                max_trusted_devices: 3,
                identity_registry_url: "https://example.com/registry".to_string(),
                weight: 0.25,
            },
        }
    }

    #[test]
    fn valid_config_passes_validation() {
        let cfg = create_valid_config();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn weights_sum_to_one() {
        let cfg = create_valid_config();
        let sum = cfg.geo_anchor.weight + cfg.network_risk.weight + cfg.device_quantity.weight;
        assert!((sum - 1.0_f32).abs() < 0.01);
    }

    #[test]
    fn invalid_weights_sum_fails_validation() {
        let mut cfg = create_valid_config();
        cfg.geo_anchor.weight = 0.5;
        cfg.network_risk.weight = 0.5;
        cfg.device_quantity.weight = 0.5; // sum = 1.5
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn missing_anchors_fails_validation() {
        let mut cfg = create_valid_config();
        cfg.geo_anchor.trusted_anchors.clear();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn weights_conversion() {
        let cfg = create_valid_config();
        let weights = cfg.weights();
        assert_eq!(weights.geo_anchor, 0.40);
        assert_eq!(weights.network_destination, 0.35);
        assert_eq!(weights.device_quantity, 0.25);
    }

    #[test]
    fn agent_section_defaults() {
        let agent = AgentSection {
            poll_interval_secs: 30,
            log_level: "DEBUG".to_string(),
            telemetry_endpoint: "https://api.example.com".to_string(),
        };
        assert_eq!(agent.poll_interval_secs, 30);
        assert_eq!(agent.log_level, "DEBUG");
    }

    #[test]
    fn multiple_anchors_valid() {
        let mut cfg = create_valid_config();
        cfg.geo_anchor.trusted_anchors = vec![
            Anchor {
                name: "HQ".to_string(),
                lat: 39.6138,
                lon: -105.0166,
            },
            Anchor {
                name: "Backup".to_string(),
                lat: 37.7749,
                lon: -122.4194,
            },
        ];
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn weights_nearly_sum_to_one_within_tolerance() {
        let mut cfg = create_valid_config();
        cfg.geo_anchor.weight = 0.40;
        cfg.network_risk.weight = 0.35;
        cfg.device_quantity.weight = 0.2499; // sum ≈ 0.9999
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn weights_sum_outside_tolerance_fails() {
        let mut cfg = create_valid_config();
        cfg.geo_anchor.weight = 0.40;
        cfg.network_risk.weight = 0.35;
        cfg.device_quantity.weight = 0.20; // sum = 0.95 (outside 1.0 ± 0.01)
        assert!(cfg.validate().is_err());
    }
}
