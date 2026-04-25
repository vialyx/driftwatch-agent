use chrono::Utc;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use driftwatch_agent::scoring::geo_anchor::GeoSource;
use driftwatch_agent::scoring::{RiskLevel, RiskScore};
use driftwatch_agent::telemetry::TelemetryEmitter;

fn make_emitter() -> TelemetryEmitter {
    TelemetryEmitter::new(
        "http://localhost:1/events".to_string(),
        "device-bench".to_string(),
        "bench@example.com".to_string(),
        b"test-signing-key-for-benchmarking".to_vec(),
        ":memory:",
    )
    .unwrap()
}

fn make_test_score() -> RiskScore {
    RiskScore {
        composite: 0.65,
        geo_anchor: 0.7,
        network_destination: 0.6,
        device_quantity: 0.65,
        level: RiskLevel::High,
        computed_at: Utc::now(),
        signals_version: "0.1.0".to_string(),
    }
}

fn benchmark_sign_payload(c: &mut Criterion) {
    let em = make_emitter();
    let payload = r#"{"event_id":"test","device_id":"device-123"}"#;

    c.bench_function("telemetry_sign_payload", |b| {
        b.iter(|| em.sign(black_box(payload)))
    });
}

fn benchmark_sign_large_payload(c: &mut Criterion) {
    let em = make_emitter();
    let payload = r#"{"event_id":"test","device_id":"device-123","signals":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20]}"#;

    c.bench_function("telemetry_sign_large_payload", |b| {
        b.iter(|| em.sign(black_box(payload)))
    });
}

fn benchmark_build_event(c: &mut Criterion) {
    let em = make_emitter();
    let score = make_test_score();

    c.bench_function("telemetry_build_event", |b| {
        b.iter(|| {
            em.build_event(
                black_box(&score),
                black_box(&GeoSource::Manual),
                black_box(50.0),
                black_box(42),
                black_box(2),
                black_box(5),
            )
        })
    });
}

fn benchmark_enqueue_event(c: &mut Criterion) {
    let em = make_emitter();
    let payload = r#"{"event_id":"test"}"#;

    c.bench_function("telemetry_enqueue_event", |b| {
        b.iter(|| {
            em.enqueue(black_box(payload)).unwrap();
        })
    });
}

fn benchmark_multiple_signs(c: &mut Criterion) {
    let em = make_emitter();

    c.bench_function("telemetry_10_signs", |b| {
        b.iter(|| {
            for i in 0..10 {
                let payload = format!(r#"{{"event_id":"event-{}"}}"#, i);
                let _ = black_box(em.sign(black_box(&payload)));
            }
        })
    });
}

criterion_group!(
    benches,
    benchmark_sign_payload,
    benchmark_sign_large_payload,
    benchmark_build_event,
    benchmark_enqueue_event,
    benchmark_multiple_signs
);
criterion_main!(benches);
