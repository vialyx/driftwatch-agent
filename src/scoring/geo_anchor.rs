use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::config::Anchor;

/// Source of the geo-location reading.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GeoSource {
    WiFiRTT,
    CoreLocation,
    GeoIP,
    WinRT,
    GeoClue2,
    Manual,
}

/// A single geo-location reading from the platform.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoReading {
    pub lat: f64,
    pub lon: f64,
    /// Estimated accuracy radius in metres.
    pub accuracy_meters: f32,
    pub source: GeoSource,
    pub timestamp: DateTime<Utc>,
}

/// Compute the haversine great-circle distance between two lat/lon points, in metres.
pub fn haversine_distance(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    const EARTH_RADIUS_M: f64 = 6_371_000.0;

    let d_lat = (lat2 - lat1).to_radians();
    let d_lon = (lon2 - lon1).to_radians();
    let lat1_r = lat1.to_radians();
    let lat2_r = lat2.to_radians();

    let a = (d_lat / 2.0).sin().powi(2) + lat1_r.cos() * lat2_r.cos() * (d_lon / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().asin();
    EARTH_RADIUS_M * c
}

/// Score a geo reading against a set of trusted anchors.
///
/// Returns a value in `[0.0, 1.0]` where 0.0 means "at a trusted anchor" and
/// 1.0 means "very far away or reading is unreliable".
pub fn score_geo_anchor(reading: &GeoReading, anchors: &[Anchor]) -> f32 {
    if anchors.is_empty() {
        // No anchors configured — treat as maximum risk.
        return 1.0;
    }

    let min_distance = anchors
        .iter()
        .map(|a| haversine_distance(reading.lat, reading.lon, a.lat, a.lon))
        .fold(f64::MAX, f64::min);

    // Linear ramp: 0 risk at 0 m, max risk at 5 km+.
    let raw = (min_distance / 5_000.0).clamp(0.0, 1.0) as f32;

    // Penalise low-accuracy readings.
    let accuracy_penalty = if reading.accuracy_meters > 200.0 {
        0.1
    } else {
        0.0
    };

    (raw + accuracy_penalty).clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hq_anchor() -> Anchor {
        Anchor {
            name: "HQ".to_string(),
            lat: 39.6138,
            lon: -105.0166,
        }
    }

    #[test]
    fn at_anchor_gives_zero_risk() {
        let reading = GeoReading {
            lat: 39.6138,
            lon: -105.0166,
            accuracy_meters: 10.0,
            source: GeoSource::Manual,
            timestamp: Utc::now(),
        };
        let score = score_geo_anchor(&reading, &[hq_anchor()]);
        assert!(score < 0.01, "expected near-zero score, got {}", score);
    }

    #[test]
    fn far_away_gives_max_risk() {
        // New York is ~2700 km from HQ
        let reading = GeoReading {
            lat: 40.7128,
            lon: -74.0060,
            accuracy_meters: 10.0,
            source: GeoSource::Manual,
            timestamp: Utc::now(),
        };
        let score = score_geo_anchor(&reading, &[hq_anchor()]);
        assert!(
            (score - 1.0).abs() < 1e-5,
            "expected max score, got {}",
            score
        );
    }

    #[test]
    fn inaccurate_reading_adds_penalty() {
        // Exactly at anchor but inaccurate
        let reading = GeoReading {
            lat: 39.6138,
            lon: -105.0166,
            accuracy_meters: 500.0, // > 200 m threshold
            source: GeoSource::Manual,
            timestamp: Utc::now(),
        };
        let score = score_geo_anchor(&reading, &[hq_anchor()]);
        assert!(
            (score - 0.1).abs() < 1e-5,
            "expected 0.10 penalty, got {}",
            score
        );
    }

    #[test]
    fn no_anchors_returns_full_risk() {
        let reading = GeoReading {
            lat: 39.6138,
            lon: -105.0166,
            accuracy_meters: 10.0,
            source: GeoSource::Manual,
            timestamp: Utc::now(),
        };
        assert_eq!(score_geo_anchor(&reading, &[]), 1.0);
    }

    #[test]
    fn haversine_distance_self_is_zero() {
        let d = haversine_distance(39.6138, -105.0166, 39.6138, -105.0166);
        assert!(d < 1e-6, "distance to self should be ~0, got {}", d);
    }

    #[test]
    fn haversine_distance_known_pair() {
        // Denver to New York ≈ 2_620 km
        let d = haversine_distance(39.7392, -104.9903, 40.7128, -74.0060);
        let km = d / 1_000.0;
        assert!((km - 2620.0).abs() < 50.0, "unexpected distance {} km", km);
    }
}
