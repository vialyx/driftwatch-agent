use chrono::Utc;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use driftwatch_agent::scoring::network_risk::{
    score_network_risk, DestinationRisk, Indicator, NetworkConnection, Protocol, ThreatFeed,
};
use std::net::IpAddr;
use std::str::FromStr;

fn make_connection(ip: &str, hostname: Option<&str>) -> NetworkConnection {
    NetworkConnection {
        remote_ip: IpAddr::from_str(ip).unwrap(),
        remote_port: 443,
        remote_hostname: hostname.map(|h| h.to_string()),
        protocol: Protocol::Tcp,
        process_name: None,
        bytes_sent: 0,
        established_at: Utc::now(),
    }
}

fn benchmark_empty_connections(c: &mut Criterion) {
    c.bench_function("network_empty_connections", |b| {
        b.iter(|| score_network_risk(black_box(&[]), black_box(&ThreatFeed::default())))
    });
}

fn benchmark_small_connection_set(c: &mut Criterion) {
    let conns = vec![
        make_connection("1.1.1.1", None),
        make_connection("8.8.8.8", None),
        make_connection("9.9.9.9", None),
        make_connection("208.67.222.222", None),
        make_connection("64.6.64.6", None),
    ];

    c.bench_function("network_5_connections", |b| {
        b.iter(|| score_network_risk(black_box(&conns), black_box(&ThreatFeed::default())))
    });
}

fn benchmark_medium_connection_set(c: &mut Criterion) {
    let mut conns = Vec::new();
    for i in 0..50 {
        conns.push(make_connection(&format!("10.0.0.{}", i % 256), None));
    }

    c.bench_function("network_50_connections", |b| {
        b.iter(|| score_network_risk(black_box(&conns), black_box(&ThreatFeed::default())))
    });
}

fn benchmark_large_connection_set(c: &mut Criterion) {
    let mut conns = Vec::new();
    for i in 0..200 {
        conns.push(make_connection(
            &format!("10.{}.{}.{}", (i / 65536) % 256, (i / 256) % 256, i % 256),
            None,
        ));
    }

    c.bench_function("network_200_connections", |b| {
        b.iter(|| score_network_risk(black_box(&conns), black_box(&ThreatFeed::default())))
    });
}

fn benchmark_with_threat_feed(c: &mut Criterion) {
    let conns = vec![
        make_connection("1.1.1.1", None),
        make_connection("192.168.0.1", None),
        make_connection("8.8.8.8", None),
    ];

    let feed = ThreatFeed::from_indicators(vec![Indicator {
        ip: Some(IpAddr::from_str("192.168.0.1").unwrap()),
        hostname: None,
        risk: DestinationRisk::Malicious,
    }]);

    c.bench_function("network_with_threat_feed", |b| {
        b.iter(|| score_network_risk(black_box(&conns), black_box(&feed)))
    });
}

fn benchmark_hostname_matching(c: &mut Criterion) {
    let conns = vec![
        make_connection("5.5.5.5", Some("trusted.example.com")),
        make_connection("6.6.6.6", Some("suspicious.example.com")),
        make_connection("7.7.7.7", Some("malicious.example.com")),
    ];

    let feed = ThreatFeed::from_indicators(vec![
        Indicator {
            ip: None,
            hostname: Some("malicious.example.com".to_string()),
            risk: DestinationRisk::Malicious,
        },
        Indicator {
            ip: None,
            hostname: Some("suspicious.example.com".to_string()),
            risk: DestinationRisk::Suspicious,
        },
    ]);

    c.bench_function("network_hostname_matching", |b| {
        b.iter(|| score_network_risk(black_box(&conns), black_box(&feed)))
    });
}

criterion_group!(
    benches,
    benchmark_empty_connections,
    benchmark_small_connection_set,
    benchmark_medium_connection_set,
    benchmark_large_connection_set,
    benchmark_with_threat_feed,
    benchmark_hostname_matching
);
criterion_main!(benches);
