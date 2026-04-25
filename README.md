# driftwatch-agent

**Cross-platform device risk scoring daemon with enterprise-grade quality assurance.**

Driftwatch Risk Scoring Agent computes a composite Device Risk Score from three real-time signals:
1. **Workspace Geo-Anchor Deviation** - Detects when devices are outside trusted locations
2. **Network Destination Risk** - Analyzes network connections against threat feeds
3. **Device Quantity** - Monitors enrollment and compliance of devices

Exposes a local IPC interface for policy enforcement and emits signed events to risk engines/SIEMs.

---

## Features

✨ **Multi-Signal Risk Assessment**
- Real-time composite scoring from independent signals
- Weighted signal combination (configurable)
- Four risk levels: Low, Medium, High, Critical

🔒 **Security & Trust**
- Device-bound HMAC-SHA256 signing
- Platform keychain integration (macOS, Windows, Linux)
- Constant-time authentication verification
- Secure IPC with bearer tokens

🌍 **Cross-Platform Support**
- **macOS** - CoreLocation (Swift bridge) + Keychain + network monitoring
- **Windows** - WinRT/.NET geolocation + Credential Manager + network monitoring
- **Linux** - GeoClue2 (D-Bus) + Secret Service + `/proc/net/*` monitoring

📊 **High Performance**
- Asynchronous event processing (Tokio)
- Local SQLite ring-buffer queue
- Exponential backoff for failed deliveries
- Optimized geo-distance calculations

---

## Quick Start

### Build

```bash
cargo build --release
```

### Run

```bash
./target/release/driftwatch-agent
```

### Test

```bash
cargo test                    # All tests (80 total)
cargo test --lib             # Unit tests only (54)
cargo test --test scoring_tests  # Integration tests (25)
DRIFTWATCH_PLATFORM_SMOKE=1 cargo test --test platform_geo_smoke  # Opt-in platform geo smoke
cargo bench                   # Run benchmarks (20 suites)
```

### Configuration

Edit `config/default.toml`:

```toml
[agent]
poll_interval_secs = 60
log_level = "INFO"
telemetry_endpoint = "https://your-api.example.com/events"

[geo_anchor]
anchor_radius_meters = 100.0
weight = 0.40
[[geo_anchor.trusted_anchors]]
name = "HQ"
lat = 39.6138
lon = -105.0166

[network_risk]
threat_feed_url = "https://threat-feed.example.com/indicators"
refresh_interval_secs = 3600
weight = 0.35

[device_quantity]
max_trusted_devices = 3
identity_registry_url = "https://registry.example.com/api"
weight = 0.25
```

---

## Architecture

### Scoring Modules

#### Geo-Anchor (`src/scoring/geo_anchor.rs`)
Scores device location against trusted anchors using haversine distance:
- At anchor: **0.0** (fully trusted)
- 5km away: **~1.0** (maximum risk)
- Accuracy penalty for imprecise readings

#### Network Risk (`src/scoring/network_risk.rs`)
Analyzes active network connections:
- Classifies destinations (trusted, unknown, suspicious, malicious)
- Returns 90th percentile risk score
- Supports IP and hostname-based threat feeds

#### Device Quantity (`src/scoring/device_quantity.rs`)
Monitors enrolled device count:
- Below max: **0.0** (no risk)
- Above max: **ln(excess) / ln(10)** (logarithmic scaling)
- Excludes devices not seen in 30 days

### IPC Interface

**Unix Socket**: `/var/run/riskagent.sock` (macOS/Linux)  
**Windows Named Pipe**: `\\.\pipe\riskagent` (Windows)

**Requests**:
```json
{"token": "AUTH_TOKEN", "method": "GET /risk/current"}
{"token": "AUTH_TOKEN", "method": "GET /risk/history", "n": 10}
{"token": "AUTH_TOKEN", "method": "GET /health"}
{"token": "AUTH_TOKEN", "method": "POST /risk/force-refresh"}
```

**Responses**:
```json
{"ok": true, "data": {"composite": 0.65, "level": "High", ...}}
{"ok": true, "data": {"status": "ok", "has_latest_score": true, "history_len": 42, "history_limit": 1000, "uptime_secs": 86400}}
{"ok": false, "error": "Authentication failed"}
```

---

## Quality Assurance

### ✅ Build Quality
- **Zero compiler warnings** - `cargo check` passes cleanly
- **Zero Clippy issues** - `cargo clippy --all-targets --all-features`
- **Formatted code** - `cargo fmt` applied throughout

### ✅ Test Coverage
- **80 Total Tests** - 100% pass rate
  - **54 Unit Tests** - Core modules (config, keychain, ipc, telemetry, scoring)
   - **26 Integration Tests** - End-to-end scoring + platform geo smoke
- Run with: `cargo test`

### ✅ Benchmarking
- **20 Performance Benchmarks** using Criterion.rs
  - Scoring computation benchmarks
  - Geo-distance calculation benchmarks
  - Network analysis benchmarks
  - Telemetry event processing benchmarks
- Run with: `cargo bench`

### ✅ CI/CD Pipeline
**6 GitHub Actions Workflows** automated on push/PR:

1. **test.yml** - Multi-platform testing
   - Platforms: Ubuntu, macOS, Windows
   - Versions: stable, beta, MSRV (1.86)
   - Coverage: unit, integration, doc tests

2. **lint.yml** - Code quality gates
   - Format checking (rustfmt)
   - Lint analysis (clippy)
   - Documentation builds

3. **build.yml** - Cross-platform builds
   - Linux (x86_64, aarch64)
   - macOS (Intel, Apple Silicon)
   - Windows (x86_64-msvc)

4. **security.yml** - Dependency scanning
   - Cargo audit (vulnerabilities)
   - Cargo deny (advisories)
   - Outdated dependency check

5. **coverage.yml** - Code coverage reporting
   - Tarpaulin-based coverage
   - Codecov integration
   - HTML report generation

6. **benchmarks.yml** - Performance tracking
   - Criterion.rs benchmark runs
   - Historical baseline comparison
   - Regression detection

---

## Dependencies

### Production
- **tokio** - Async runtime
- **serde/serde_json** - Serialization
- **reqwest** - HTTP client
- **rusqlite** - SQLite integration
- **chrono** - Time handling
- **hmac/sha2** - Cryptographic signing
- **config** - Configuration management
- **tracing** - Structured logging
- **keyring** - Platform credential storage
- **Platform-specific**: objc2, windows, zbus

### Development
- **criterion** - Benchmarking framework
- **approx** - Floating-point assertions
- **tempfile** - Temporary file utilities

---

## Documentation

Comprehensive guides included:

- **[IMPROVEMENTS.md](IMPROVEMENTS.md)** (416 lines)
  - Complete implementation details
  - Metrics and statistics
  - Configuration guide
  - Performance tuning

- **[QUICK_REFERENCE.md](QUICK_REFERENCE.md)** (258 lines)
  - Command reference
  - Test execution examples
  - Troubleshooting guide
  - Architecture overview

- **[MANIFEST.md](MANIFEST.md)**
  - Complete change list
  - File inventory
  - Verification results

---

## Development

### Local Setup

```bash
# Clone repository
git clone https://github.com/yourusername/driftwatch-agent
cd driftwatch-agent

# Build
cargo build

# Run tests
cargo test

# Run benchmarks
cargo bench

# Format code
cargo fmt

# Check quality
cargo clippy --all-targets --all-features
```

### Running Tests

```bash
# All tests
cargo test

# Unit tests only
cargo test --lib

# Integration tests
cargo test --test scoring_tests

# Specific test with output
cargo test test_name -- --nocapture

# With backtrace
RUST_BACKTRACE=1 cargo test
```

### Running Benchmarks

```bash
# All benchmarks
cargo bench

# Specific suite
cargo bench --bench scoring_benches

# View results
open target/criterion/report/index.html  # macOS
xdg-open target/criterion/report/index.html  # Linux
```

### Code Quality

```bash
# Format check
cargo fmt -- --check

# Auto-format
cargo fmt

# Clippy analysis
cargo clippy --all-targets --all-features

# Type checking
cargo check --all-features

# Full release build
cargo build --release
```

---

## Platform Support

| Platform | Status | Notes |
|----------|--------|-------|
| macOS (Intel) | ✅ | Core Location, WiFi RTT, Keychain |
| macOS (Apple Silicon) | ✅ | Native arm64 support |
| Linux (x86_64) | ✅ | GeoClue2, Secret Service |
| Linux (aarch64) | ✅ | ARM64 native support |
| Windows (x86_64) | ✅ | Geolocation API, Credential Manager |

---

## Performance

### Benchmarks (macOS, M1)

| Operation | Time |
|-----------|------|
| Composite scoring | ~1-5 µs |
| Haversine distance | ~500 ns - 2 µs |
| Network analysis (100 conns) | ~10-50 µs |
| Event signing | ~50-100 µs |

### Memory Usage

- Base daemon: ~20-30 MB
- SQLite queue: Ring buffer (max 1000 events, ~5 MB)
- IPC connections: Per-connection overhead minimal

---

## Troubleshooting

### Tests Fail
```bash
RUST_BACKTRACE=1 cargo test
```

### Benchmarks Unstable
```bash
cargo bench -- --warm-up-time 10 --sample-size 1000
```

### Build Issues
```bash
cargo clean
cargo build --release
```

### Dependency Problems
```bash
cargo update
cargo tree  # View dependency graph
```

---

## Security Considerations

- All events signed with device-bound keys (HMAC-SHA256)
- Credentials stored in platform keychains (encrypted at rest)
- IPC authentication with bearer tokens
- Constant-time token comparison (prevents timing attacks)
- No sensitive data logged (only risk scores)

---

## Contributing

1. Run full test suite: `cargo test`
2. Format code: `cargo fmt`
3. Check quality: `cargo clippy --all-targets --all-features`
4. Compile benchmarks: `cargo bench --no-run`
5. All checks must pass before PR submission

---

## License

Apache License 2.0 - See [LICENSE](LICENSE)

---

## Resources

- [Rust Book](https://doc.rust-lang.org/book/)
- [Tokio Documentation](https://tokio.rs/)
- [Criterion.rs](https://bheisler.github.io/criterion.rs/book/)
- [GitHub Actions](https://docs.github.com/en/actions)
