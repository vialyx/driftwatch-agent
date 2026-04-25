//! Platform geolocation smoke tests.
//!
//! These tests are intentionally opt-in because they require host capabilities
//! (OS location services permissions and/or outbound network for GeoIP fallback).
//! Enable with:
//!   DRIFTWATCH_PLATFORM_SMOKE=1 cargo test --test platform_geo_smoke

use driftwatch_agent::platform::GeoProvider;
use driftwatch_agent::scoring::geo_anchor::GeoReading;

fn smoke_enabled() -> bool {
    match std::env::var("DRIFTWATCH_PLATFORM_SMOKE") {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            v == "1" || v == "true" || v == "yes"
        }
        Err(_) => false,
    }
}

fn assert_reading_valid(reading: &GeoReading) {
    assert!(
        (-90.0..=90.0).contains(&reading.lat),
        "latitude out of range: {}",
        reading.lat
    );
    assert!(
        (-180.0..=180.0).contains(&reading.lon),
        "longitude out of range: {}",
        reading.lon
    );
    assert!(
        reading.accuracy_meters.is_finite(),
        "accuracy must be finite, got {}",
        reading.accuracy_meters
    );
    assert!(
        reading.accuracy_meters >= 0.0,
        "accuracy must be non-negative, got {}",
        reading.accuracy_meters
    );
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn macos_geo_provider_smoke() {
    if !smoke_enabled() {
        eprintln!("Skipping macOS geolocation smoke test (set DRIFTWATCH_PLATFORM_SMOKE=1)");
        return;
    }

    let provider = driftwatch_agent::platform::macos::MacOsGeoProvider;
    let reading = provider
        .current_reading()
        .await
        .expect("macOS geolocation provider should return a reading");
    assert_reading_valid(&reading);
}

#[cfg(target_os = "windows")]
#[tokio::test]
async fn windows_geo_provider_smoke() {
    if !smoke_enabled() {
        eprintln!("Skipping Windows geolocation smoke test (set DRIFTWATCH_PLATFORM_SMOKE=1)");
        return;
    }

    let provider = driftwatch_agent::platform::windows::WindowsGeoProvider;
    let reading = provider
        .current_reading()
        .await
        .expect("Windows geolocation provider should return a reading");
    assert_reading_valid(&reading);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn linux_geo_provider_smoke() {
    if !smoke_enabled() {
        eprintln!("Skipping Linux geolocation smoke test (set DRIFTWATCH_PLATFORM_SMOKE=1)");
        return;
    }

    let provider = driftwatch_agent::platform::linux::LinuxGeoProvider;
    let reading = provider
        .current_reading()
        .await
        .expect("Linux geolocation provider should return a reading");
    assert_reading_valid(&reading);
}
