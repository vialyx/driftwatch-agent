use criterion::{black_box, criterion_group, criterion_main, Criterion};
use driftwatch_agent::scoring::{compute_composite, Weights};

fn benchmark_composite_scoring(c: &mut Criterion) {
    let weights = Weights {
        geo_anchor: 0.40,
        network_destination: 0.35,
        device_quantity: 0.25,
    };

    c.bench_function("compute_composite_low_risk", |b| {
        b.iter(|| {
            compute_composite(
                black_box(0.1),
                black_box(0.2),
                black_box(0.15),
                black_box(&weights),
            )
        })
    });

    c.bench_function("compute_composite_medium_risk", |b| {
        b.iter(|| {
            compute_composite(
                black_box(0.4),
                black_box(0.5),
                black_box(0.3),
                black_box(&weights),
            )
        })
    });

    c.bench_function("compute_composite_high_risk", |b| {
        b.iter(|| {
            compute_composite(
                black_box(0.7),
                black_box(0.8),
                black_box(0.9),
                black_box(&weights),
            )
        })
    });

    c.bench_function("compute_composite_critical_risk", |b| {
        b.iter(|| {
            compute_composite(
                black_box(1.0),
                black_box(1.0),
                black_box(1.0),
                black_box(&weights),
            )
        })
    });
}

fn benchmark_risk_level_mapping(c: &mut Criterion) {
    let weights = Weights {
        geo_anchor: 0.40,
        network_destination: 0.35,
        device_quantity: 0.25,
    };

    let test_cases = vec![
        (0.1, 0.1, 0.1),
        (0.3, 0.3, 0.3),
        (0.5, 0.5, 0.5),
        (0.7, 0.7, 0.7),
        (0.9, 0.9, 0.9),
    ];

    c.bench_function("risk_level_classification", |b| {
        b.iter(|| {
            for (geo, net, dev) in &test_cases {
                let score = compute_composite(
                    black_box(*geo),
                    black_box(*net),
                    black_box(*dev),
                    black_box(&weights),
                );
                let _ = black_box(score.level);
            }
        })
    });
}

criterion_group!(
    benches,
    benchmark_composite_scoring,
    benchmark_risk_level_mapping
);
criterion_main!(benches);
