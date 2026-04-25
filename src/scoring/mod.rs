use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub mod device_quantity;
pub mod geo_anchor;
pub mod network_risk;

/// Signal weights used when computing the composite score.
#[derive(Debug, Clone, Copy)]
pub struct Weights {
    pub geo_anchor: f32,
    pub network_destination: f32,
    pub device_quantity: f32,
}

/// Composite device risk score with per-signal breakdown.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScore {
    /// Composite 0.0–1.0 score.
    pub composite: f32,
    pub geo_anchor: f32,
    pub network_destination: f32,
    pub device_quantity: f32,
    pub level: RiskLevel,
    pub computed_at: DateTime<Utc>,
    pub signals_version: String,
}

/// Human-readable risk level bucketed from the composite score.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,      // composite < 0.30
    Medium,   // 0.30 – 0.59
    High,     // 0.60 – 0.79
    Critical, // >= 0.80
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskLevel::Low => write!(f, "Low"),
            RiskLevel::Medium => write!(f, "Medium"),
            RiskLevel::High => write!(f, "High"),
            RiskLevel::Critical => write!(f, "Critical"),
        }
    }
}

/// Compute the weighted composite risk score from individual signal scores.
pub fn compute_composite(geo: f32, network: f32, device: f32, weights: &Weights) -> RiskScore {
    let composite = (geo * weights.geo_anchor
        + network * weights.network_destination
        + device * weights.device_quantity)
        .clamp(0.0, 1.0);

    let level = match composite {
        s if s < 0.30 => RiskLevel::Low,
        s if s < 0.60 => RiskLevel::Medium,
        s if s < 0.80 => RiskLevel::High,
        _ => RiskLevel::Critical,
    };

    RiskScore {
        composite,
        geo_anchor: geo,
        network_destination: network,
        device_quantity: device,
        level,
        computed_at: Utc::now(),
        signals_version: env!("CARGO_PKG_VERSION").to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_weights() -> Weights {
        Weights {
            geo_anchor: 0.40,
            network_destination: 0.35,
            device_quantity: 0.25,
        }
    }

    #[test]
    fn all_zero_signals_give_low_level() {
        let score = compute_composite(0.0, 0.0, 0.0, &default_weights());
        assert_eq!(score.composite, 0.0);
        assert_eq!(score.level, RiskLevel::Low);
    }

    #[test]
    fn all_one_signals_give_critical_level() {
        let score = compute_composite(1.0, 1.0, 1.0, &default_weights());
        assert!((score.composite - 1.0).abs() < 1e-5);
        assert_eq!(score.level, RiskLevel::Critical);
    }

    #[test]
    fn level_boundaries() {
        let w = Weights {
            geo_anchor: 1.0,
            network_destination: 0.0,
            device_quantity: 0.0,
        };
        assert_eq!(compute_composite(0.29, 0.0, 0.0, &w).level, RiskLevel::Low);
        assert_eq!(
            compute_composite(0.30, 0.0, 0.0, &w).level,
            RiskLevel::Medium
        );
        assert_eq!(
            compute_composite(0.59, 0.0, 0.0, &w).level,
            RiskLevel::Medium
        );
        assert_eq!(compute_composite(0.60, 0.0, 0.0, &w).level, RiskLevel::High);
        assert_eq!(compute_composite(0.79, 0.0, 0.0, &w).level, RiskLevel::High);
        assert_eq!(
            compute_composite(0.80, 0.0, 0.0, &w).level,
            RiskLevel::Critical
        );
    }
}
