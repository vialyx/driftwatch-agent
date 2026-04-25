use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Protocol used by a network connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
}

/// A single outbound network connection observed on the device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    pub remote_ip: IpAddr,
    pub remote_port: u16,
    pub remote_hostname: Option<String>,
    pub protocol: Protocol,
    pub process_name: Option<String>,
    pub bytes_sent: u64,
    pub established_at: DateTime<Utc>,
}

/// Threat classification for a network destination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DestinationRisk {
    Trusted,    // known-good (CDN, corporate)
    Unknown,    // no intel available
    Suspicious, // low-confidence threat signal
    Malicious,  // confirmed IOC / blocklist hit
}

/// A threat intelligence indicator entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Indicator {
    pub ip: Option<IpAddr>,
    pub hostname: Option<String>,
    pub risk: DestinationRisk,
}

/// In-memory threat feed loaded from the remote URL.
#[derive(Debug, Default, Clone)]
pub struct ThreatFeed {
    indicators: Vec<Indicator>,
}

impl ThreatFeed {
    pub fn from_indicators(indicators: Vec<Indicator>) -> Self {
        Self { indicators }
    }

    /// Classify a connection by IP and optional hostname.
    pub fn classify(&self, ip: &IpAddr, hostname: Option<&str>) -> DestinationRisk {
        for ind in &self.indicators {
            if let Some(ref ind_ip) = ind.ip {
                if ind_ip == ip {
                    return ind.risk.clone();
                }
            }
            if let (Some(ref ind_host), Some(conn_host)) = (&ind.hostname, &hostname) {
                if ind_host.eq_ignore_ascii_case(conn_host) {
                    return ind.risk.clone();
                }
            }
        }
        DestinationRisk::Unknown
    }
}

/// Compute the 90th-percentile network risk score across all active connections.
///
/// Returns a value in `[0.0, 1.0]`.
pub fn score_network_risk(connections: &[NetworkConnection], feed: &ThreatFeed) -> f32 {
    if connections.is_empty() {
        return 0.0;
    }

    let mut scores: Vec<f32> = connections
        .iter()
        .map(|conn| {
            match feed.classify(&conn.remote_ip, conn.remote_hostname.as_deref()) {
                DestinationRisk::Trusted => 0.0,
                DestinationRisk::Unknown => 0.2,
                DestinationRisk::Suspicious => 0.6,
                DestinationRisk::Malicious => 1.0,
            }
        })
        .collect();

    percentile_90(&mut scores)
}

/// Compute the 90th percentile of a mutable slice of scores.
///
/// Uses the nearest-rank method: `index = floor(0.90 * n)`, so the last
/// element becomes the 90th percentile for n ≤ 10 (ensuring that a single
/// malicious connection in 10 is captured at the top of the distribution).
///
/// The slice is sorted in-place.
fn percentile_90(scores: &mut [f32]) -> f32 {
    if scores.is_empty() {
        return 0.0;
    }
    scores.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    // Nearest-rank: floor(p * n), clamped to valid index range.
    let idx = ((scores.len() as f32 * 0.90).floor() as usize).min(scores.len() - 1);
    scores[idx]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::str::FromStr;

    fn ip(s: &str) -> IpAddr {
        IpAddr::from_str(s).unwrap()
    }

    fn conn(remote_ip: IpAddr, hostname: Option<&str>) -> NetworkConnection {
        NetworkConnection {
            remote_ip,
            remote_port: 443,
            remote_hostname: hostname.map(|s| s.to_string()),
            protocol: Protocol::Tcp,
            process_name: None,
            bytes_sent: 1024,
            established_at: Utc::now(),
        }
    }

    #[test]
    fn empty_connections_returns_zero() {
        let feed = ThreatFeed::default();
        assert_eq!(score_network_risk(&[], &feed), 0.0);
    }

    #[test]
    fn all_trusted_returns_zero() {
        let indicators = vec![Indicator {
            ip: Some(ip("1.2.3.4")),
            hostname: None,
            risk: DestinationRisk::Trusted,
        }];
        let feed = ThreatFeed::from_indicators(indicators);
        let conns = vec![conn(ip("1.2.3.4"), None)];
        assert_eq!(score_network_risk(&conns, &feed), 0.0);
    }

    #[test]
    fn malicious_connection_drives_score_high() {
        let indicators = vec![Indicator {
            ip: Some(ip("10.0.0.1")),
            hostname: None,
            risk: DestinationRisk::Malicious,
        }];
        let feed = ThreatFeed::from_indicators(indicators);
        // 9 benign + 1 malicious → 90th percentile should be 1.0
        let mut conns: Vec<NetworkConnection> = (0..9)
            .map(|i| conn(ip(&format!("192.168.1.{}", i + 1)), None))
            .collect();
        conns.push(conn(ip("10.0.0.1"), None));
        let score = score_network_risk(&conns, &feed);
        assert!(
            (score - 1.0).abs() < 1e-5,
            "expected 1.0, got {}",
            score
        );
    }

    #[test]
    fn unknown_connections_score_0_2() {
        let feed = ThreatFeed::default();
        let conns = vec![conn(ip("8.8.8.8"), None)];
        assert!((score_network_risk(&conns, &feed) - 0.2).abs() < 1e-5);
    }

    #[test]
    fn hostname_classification() {
        let indicators = vec![Indicator {
            ip: None,
            hostname: Some("evil.example.com".to_string()),
            risk: DestinationRisk::Suspicious,
        }];
        let feed = ThreatFeed::from_indicators(indicators);
        let conns = vec![conn(ip("5.5.5.5"), Some("evil.example.com"))];
        assert!((score_network_risk(&conns, &feed) - 0.6).abs() < 1e-5);
    }

    #[test]
    fn percentile_single_element() {
        let mut v = vec![0.5_f32];
        assert!((percentile_90(&mut v) - 0.5).abs() < 1e-5);
    }

    #[test]
    fn percentile_ten_elements() {
        // [0.0, 0.1, 0.2, ..., 0.9] → 90th pct = 0.9
        let mut v: Vec<f32> = (0..10).map(|i| i as f32 / 10.0).collect();
        let p = percentile_90(&mut v);
        assert!((p - 0.9).abs() < 1e-5, "got {}", p);
    }
}
