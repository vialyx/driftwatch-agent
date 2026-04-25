use criterion::{black_box, criterion_group, criterion_main, Criterion};
use driftwatch_agent::scoring::geo_anchor::haversine_distance;

fn benchmark_haversine_short_distance(c: &mut Criterion) {
    c.bench_function("haversine_500m", |b| {
        b.iter(|| {
            haversine_distance(
                black_box(39.6138),
                black_box(-105.0166),
                black_box(39.6183),
                black_box(-105.0166),
            )
        })
    });
}

fn benchmark_haversine_medium_distance(c: &mut Criterion) {
    // London to Paris (~340 km)
    c.bench_function("haversine_340km", |b| {
        b.iter(|| {
            haversine_distance(
                black_box(51.5074),
                black_box(-0.1278),
                black_box(48.8566),
                black_box(2.3522),
            )
        })
    });
}

fn benchmark_haversine_long_distance(c: &mut Criterion) {
    // New York to Tokyo (~10,850 km)
    c.bench_function("haversine_10850km", |b| {
        b.iter(|| {
            haversine_distance(
                black_box(40.7128),
                black_box(-74.0060),
                black_box(35.6762),
                black_box(139.6503),
            )
        })
    });
}

fn benchmark_haversine_antimeridian(c: &mut Criterion) {
    // Across the antimeridian
    c.bench_function("haversine_antimeridian", |b| {
        b.iter(|| {
            haversine_distance(
                black_box(0.0),
                black_box(170.0),
                black_box(0.0),
                black_box(-170.0),
            )
        })
    });
}

fn benchmark_haversine_same_location(c: &mut Criterion) {
    c.bench_function("haversine_same_location", |b| {
        b.iter(|| {
            haversine_distance(
                black_box(51.5074),
                black_box(-0.1278),
                black_box(51.5074),
                black_box(-0.1278),
            )
        })
    });
}

criterion_group!(
    benches,
    benchmark_haversine_short_distance,
    benchmark_haversine_medium_distance,
    benchmark_haversine_long_distance,
    benchmark_haversine_antimeridian,
    benchmark_haversine_same_location
);
criterion_main!(benches);
