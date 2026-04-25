//! Integration-style scoring tests covering all three signal modules,
//! the composite scorer, and telemetry signing.

use chrono::{Duration, Utc};
use std::net::IpAddr;
use std::str::FromStr;

// Re-export scoring internals for test access.
use driftwatch_agent::scoring::{
    compute_composite,
    device_quantity::{score_device_quantity, ComplianceState, EnrolledDevice},
    geo_anchor::{haversine_distance, score_geo_anchor, GeoReading, GeoSource},
    network_risk::{
        score_network_risk, DestinationRisk, Indicator, NetworkConnection, Protocol, ThreatFeed,
    },
    RiskLevel, Weights,
};

// ---------------------------------------------------------------------------
// Helper constructors
// ---------------------------------------------------------------------------

fn anchor(name: &str, lat: f64, lon: f64) -> driftwatch_agent::config::Anchor {
    driftwatch_agent::config::Anchor {
        name: name.to_string(),
        lat,
        lon,
    }
}

fn geo_reading(lat: f64, lon: f64, accuracy_meters: f32) -> GeoReading {
    GeoReading {
        lat,
        lon,
        accuracy_meters,
        source: GeoSource::Manual,
        timestamp: Utc::now(),
    }
}

fn ip(s: &str) -> IpAddr {
    IpAddr::from_str(s).unwrap()
}

fn tcp_conn(remote_ip: IpAddr, hostname: Option<&str>) -> NetworkConnection {
    NetworkConnection {
        remote_ip,
        remote_port: 443,
        remote_hostname: hostname.map(|h| h.to_string()),
        protocol: Protocol::Tcp,
        process_name: None,
        bytes_sent: 0,
        established_at: Utc::now(),
    }
}

fn active_device() -> EnrolledDevice {
    EnrolledDevice {
        device_id: uuid::Uuid::new_v4().to_string(),
        platform: "macOS".to_string(),
        last_seen: Utc::now() - Duration::days(1),
        compliance_state: ComplianceState::Compliant,
        is_current: false,
    }
}

fn stale_device() -> EnrolledDevice {
    EnrolledDevice {
        device_id: uuid::Uuid::new_v4().to_string(),
        platform: "Windows".to_string(),
        last_seen: Utc::now() - Duration::days(45),
        compliance_state: ComplianceState::Unknown,
        is_current: false,
    }
}

// ---------------------------------------------------------------------------
// Geo-anchor tests
// ---------------------------------------------------------------------------

#[test]
fn geo_at_anchor_zero_score() {
    let hq = anchor("HQ", 39.6138, -105.0166);
    let reading = geo_reading(39.6138, -105.0166, 10.0);
    let score = score_geo_anchor(&reading, &[hq]);
    assert!(score < 0.01, "at anchor → score should be ~0, got {}", score);
}

#[test]
fn geo_500m_low_score() {
    // ~500 m north of HQ
    let hq = anchor("HQ", 39.6138, -105.0166);
    let reading = geo_reading(39.6183, -105.0166, 10.0); // ~500 m north
    let score = score_geo_anchor(&reading, &[hq]);
    assert!(
        score < 0.12,
        "500 m from anchor → score should be low, got {}",
        score
    );
}

#[test]
fn geo_beyond_5km_max_score() {
    let hq = anchor("HQ", 39.6138, -105.0166);
    // Tokyo
    let reading = geo_reading(35.6762, 139.6503, 10.0);
    let score = score_geo_anchor(&reading, &[hq]);
    assert!(
        (score - 1.0).abs() < 1e-5,
        "far away → score should be 1.0, got {}",
        score
    );
}

#[test]
fn geo_inaccurate_reading_penalty() {
    let hq = anchor("HQ", 39.6138, -105.0166);
    let reading = geo_reading(39.6138, -105.0166, 300.0); // at anchor but inaccurate
    let score = score_geo_anchor(&reading, &[hq]);
    // raw=0 + penalty=0.1 → 0.1
    assert!(
        (score - 0.1).abs() < 1e-5,
        "inaccurate reading → 0.1, got {}",
        score
    );
}

#[test]
fn geo_no_anchors_returns_one() {
    let reading = geo_reading(39.6138, -105.0166, 10.0);
    assert_eq!(score_geo_anchor(&reading, &[]), 1.0);
}

#[test]
fn haversine_self_zero() {
    let d = haversine_distance(51.5074, -0.1278, 51.5074, -0.1278);
    assert!(d < 1e-6, "distance to self ≈ 0, got {}", d);
}

#[test]
fn haversine_london_paris_approx() {
    // London → Paris ≈ 340 km
    let d = haversine_distance(51.5074, -0.1278, 48.8566, 2.3522);
    let km = d / 1_000.0;
    assert!(
        (km - 340.0).abs() < 15.0,
        "London→Paris should be ~340 km, got {} km",
        km
    );
}

// ---------------------------------------------------------------------------
// Network risk tests
// ---------------------------------------------------------------------------

#[test]
fn network_empty_connections_zero() {
    assert_eq!(score_network_risk(&[], &ThreatFeed::default()), 0.0);
}

#[test]
fn network_all_unknown_gives_0_2() {
    let conns = vec![tcp_conn(ip("1.1.1.1"), None), tcp_conn(ip("8.8.8.8"), None)];
    let score = score_network_risk(&conns, &ThreatFeed::default());
    assert!(
        (score - 0.2).abs() < 1e-5,
        "all unknown → 0.2, got {}",
        score
    );
}

#[test]
fn network_single_malicious_connection_drives_high_score() {
    let feed = ThreatFeed::from_indicators(vec![Indicator {
        ip: Some(ip("192.168.0.1")),
        hostname: None,
        risk: DestinationRisk::Malicious,
    }]);
    // 9 unknown + 1 malicious → 90th pct = 1.0
    let mut conns: Vec<NetworkConnection> =
        (1..10).map(|i| tcp_conn(ip(&format!("10.0.0.{}", i)), None)).collect();
    conns.push(tcp_conn(ip("192.168.0.1"), None));
    let score = score_network_risk(&conns, &feed);
    assert!(
        (score - 1.0).abs() < 1e-5,
        "one malicious in 10 → 90th pct = 1.0, got {}",
        score
    );
}

#[test]
fn network_trusted_connections_zero() {
    let feed = ThreatFeed::from_indicators(vec![Indicator {
        ip: Some(ip("1.1.1.1")),
        hostname: None,
        risk: DestinationRisk::Trusted,
    }]);
    let conns = vec![tcp_conn(ip("1.1.1.1"), None)];
    assert_eq!(score_network_risk(&conns, &feed), 0.0);
}

#[test]
fn network_hostname_match() {
    let feed = ThreatFeed::from_indicators(vec![Indicator {
        ip: None,
        hostname: Some("bad.example.com".to_string()),
        risk: DestinationRisk::Suspicious,
    }]);
    let conns = vec![tcp_conn(ip("5.5.5.5"), Some("bad.example.com"))];
    let score = score_network_risk(&conns, &feed);
    assert!((score - 0.6).abs() < 1e-5, "suspicious → 0.6, got {}", score);
}

// ---------------------------------------------------------------------------
// Device quantity tests
// ---------------------------------------------------------------------------

#[test]
fn device_zero_returns_zero() {
    assert_eq!(score_device_quantity(&[], 3), 0.0);
}

#[test]
fn device_at_max_trusted_returns_zero() {
    let devices: Vec<_> = (0..3).map(|_| active_device()).collect();
    assert_eq!(score_device_quantity(&devices, 3), 0.0);
}

#[test]
fn device_one_over_max_returns_zero() {
    // excess=1 → ln(1)/ln(10) = 0
    let devices: Vec<_> = (0..4).map(|_| active_device()).collect();
    let score = score_device_quantity(&devices, 3);
    assert!(score.abs() < 1e-5, "expected ~0, got {}", score);
}

#[test]
fn device_ten_over_max_returns_high_score() {
    // active=13 (max=3) → excess=10 → ln(10)/ln(10)=1.0
    let devices: Vec<_> = (0..13).map(|_| active_device()).collect();
    let score = score_device_quantity(&devices, 3);
    assert!(
        (score - 1.0).abs() < 1e-5,
        "excess=10 → 1.0, got {}",
        score
    );
}

#[test]
fn device_stale_not_counted() {
    let mut devices: Vec<_> = (0..2).map(|_| active_device()).collect();
    devices.extend((0..10).map(|_| stale_device()));
    // Only 2 active → below max_trusted=3
    assert_eq!(score_device_quantity(&devices, 3), 0.0);
}

#[test]
fn device_score_clamped_to_one() {
    let devices: Vec<_> = (0..1003).map(|_| active_device()).collect();
    let score = score_device_quantity(&devices, 3);
    assert!(score <= 1.0);
}

// ---------------------------------------------------------------------------
// Composite scorer tests
// ---------------------------------------------------------------------------

fn default_weights() -> Weights {
    Weights {
        geo_anchor: 0.40,
        network_destination: 0.35,
        device_quantity: 0.25,
    }
}

#[test]
fn composite_zero_is_low() {
    let s = compute_composite(0.0, 0.0, 0.0, &default_weights());
    assert_eq!(s.level, RiskLevel::Low);
    assert_eq!(s.composite, 0.0);
}

#[test]
fn composite_one_is_critical() {
    let s = compute_composite(1.0, 1.0, 1.0, &default_weights());
    assert_eq!(s.level, RiskLevel::Critical);
    assert!((s.composite - 1.0).abs() < 1e-5);
}

#[test]
fn composite_medium_boundary() {
    // composite ≈ 0.30 with weights
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
}

#[test]
fn composite_high_boundary() {
    let w = Weights {
        geo_anchor: 1.0,
        network_destination: 0.0,
        device_quantity: 0.0,
    };
    assert_eq!(
        compute_composite(0.59, 0.0, 0.0, &w).level,
        RiskLevel::Medium
    );
    assert_eq!(compute_composite(0.60, 0.0, 0.0, &w).level, RiskLevel::High);
}

#[test]
fn composite_critical_boundary() {
    let w = Weights {
        geo_anchor: 1.0,
        network_destination: 0.0,
        device_quantity: 0.0,
    };
    assert_eq!(compute_composite(0.79, 0.0, 0.0, &w).level, RiskLevel::High);
    assert_eq!(
        compute_composite(0.80, 0.0, 0.0, &w).level,
        RiskLevel::Critical
    );
}

#[test]
fn composite_weight_arithmetic() {
    let w = Weights {
        geo_anchor: 0.40,
        network_destination: 0.35,
        device_quantity: 0.25,
    };
    let s = compute_composite(0.5, 0.5, 0.5, &w);
    // 0.5*0.40 + 0.5*0.35 + 0.5*0.25 = 0.5
    assert!(
        (s.composite - 0.5).abs() < 1e-5,
        "expected 0.5, got {}",
        s.composite
    );
}

#[test]
fn composite_clamps_above_one() {
    // Deliberately uses weights that sum > 1.0 to exercise the clamp guard
    // in `compute_composite`.  Config validation would reject these weights
    // at startup in production, but the arithmetic clamp is an independent
    // safety net.
    let w = Weights {
        geo_anchor: 0.60,
        network_destination: 0.60,
        device_quantity: 0.60,
    };
    let s = compute_composite(1.0, 1.0, 1.0, &w);
    assert!(s.composite <= 1.0);
}
