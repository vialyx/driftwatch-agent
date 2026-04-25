// build.rs — platform feature detection
fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    println!("cargo:rustc-env=DRIFTWATCH_TARGET_OS={}", target_os);
    println!("cargo:rerun-if-changed=build.rs");
}
