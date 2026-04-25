use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

/// Compliance state of an enrolled device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComplianceState {
    Compliant,
    NonCompliant,
    Unknown,
}

/// An enrolled device associated with the authenticated identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrolledDevice {
    pub device_id: String,
    pub platform: String,
    pub last_seen: DateTime<Utc>,
    pub compliance_state: ComplianceState,
    pub is_current: bool,
}

/// Score based on the number of recently active enrolled devices.
///
/// Devices are considered active if their `last_seen` timestamp is within the
/// last 30 days. Returns a value in `[0.0, 1.0]`.
pub fn score_device_quantity(devices: &[EnrolledDevice], max_trusted: usize) -> f32 {
    let cutoff = Utc::now() - Duration::days(30);
    let active = devices.iter().filter(|d| d.last_seen > cutoff).count();

    if active <= max_trusted {
        return 0.0;
    }

    // Logarithmic growth: sharp rise from max_trusted+1, diminishing returns
    // at very high counts.  Uses natural log normalised by ln(10).
    let excess = (active - max_trusted) as f32;
    (excess.ln() / (10.0_f32).ln()).clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(days_ago: i64) -> EnrolledDevice {
        EnrolledDevice {
            device_id: uuid::Uuid::new_v4().to_string(),
            platform: "macOS".to_string(),
            last_seen: Utc::now() - Duration::days(days_ago),
            compliance_state: ComplianceState::Compliant,
            is_current: false,
        }
    }

    #[test]
    fn zero_devices_gives_zero() {
        assert_eq!(score_device_quantity(&[], 3), 0.0);
    }

    #[test]
    fn at_max_trusted_gives_zero() {
        let devices: Vec<_> = (0..3).map(|_| device(1)).collect();
        assert_eq!(score_device_quantity(&devices, 3), 0.0);
    }

    #[test]
    fn one_over_max_gives_near_zero() {
        // excess = 1 → ln(1)/ln(10) = 0.0
        let devices: Vec<_> = (0..4).map(|_| device(1)).collect();
        let score = score_device_quantity(&devices, 3);
        assert!(score.abs() < 1e-5, "expected ~0.0, got {}", score);
    }

    #[test]
    fn five_over_max_gives_elevated_score() {
        // active=8 (max_trusted=3) → excess=5 → ln(5)/ln(10) ≈ 0.699
        let devices: Vec<_> = (0..8).map(|_| device(1)).collect();
        let score = score_device_quantity(&devices, 3);
        let expected = (5.0_f32).ln() / (10.0_f32).ln();
        assert!(
            (score - expected).abs() < 1e-5,
            "expected {}, got {}",
            expected,
            score
        );
    }

    #[test]
    fn stale_devices_not_counted() {
        // 2 active + 5 stale (31 days ago) = below max_trusted of 3
        let mut devices: Vec<_> = (0..2).map(|_| device(1)).collect();
        devices.extend((0..5).map(|_| device(31)));
        assert_eq!(score_device_quantity(&devices, 3), 0.0);
    }

    #[test]
    fn very_high_count_clamped_to_one() {
        // 1003 devices over max_trusted=3 → excess=1000 → would exceed 1.0 without clamp
        let devices: Vec<_> = (0..1003).map(|_| device(1)).collect();
        let score = score_device_quantity(&devices, 3);
        assert!(score <= 1.0, "score {} exceeds 1.0", score);
        assert!(score > 0.9, "expected near-max score, got {}", score);
    }
}
