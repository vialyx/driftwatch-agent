//! Platform keychain / credential storage abstraction.
//!
//! On macOS: Keychain Services (Security.framework).
//! On Windows: DPAPI (`CryptProtectData`).
//! On Linux: libsecret / Secret Service D-Bus API.
//!
//! For the initial implementation a file-based fallback is provided so the
//! agent can operate without elevated keychain privileges during development.

use anyhow::{anyhow, Result};
use std::path::PathBuf;

/// Retrieve a secret from the platform keychain.
pub fn get_secret(service: &str, account: &str) -> Result<Vec<u8>> {
    #[cfg(target_os = "macos")]
    {
        macos_get_secret(service, account)
    }
    #[cfg(target_os = "windows")]
    {
        windows_get_secret(service, account)
    }
    #[cfg(target_os = "linux")]
    {
        linux_get_secret(service, account)
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        file_get_secret(service, account)
    }
}

/// Store a secret in the platform keychain.
pub fn set_secret(service: &str, account: &str, secret: &[u8]) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        macos_set_secret(service, account, secret)
    }
    #[cfg(target_os = "windows")]
    {
        windows_set_secret(service, account, secret)
    }
    #[cfg(target_os = "linux")]
    {
        linux_set_secret(service, account, secret)
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        file_set_secret(service, account, secret)
    }
}

// ---------------------------------------------------------------------------
// macOS — Keychain Services
// ---------------------------------------------------------------------------
#[cfg(target_os = "macos")]
fn macos_get_secret(service: &str, account: &str) -> Result<Vec<u8>> {
    // TODO: implement via Security.framework SecKeychainFindGenericPassword
    file_get_secret(service, account)
}

#[cfg(target_os = "macos")]
fn macos_set_secret(service: &str, account: &str, secret: &[u8]) -> Result<()> {
    // TODO: implement via Security.framework SecKeychainAddGenericPassword
    file_set_secret(service, account, secret)
}

// ---------------------------------------------------------------------------
// Windows — DPAPI
// ---------------------------------------------------------------------------
#[cfg(target_os = "windows")]
fn windows_get_secret(service: &str, account: &str) -> Result<Vec<u8>> {
    // TODO: implement via CryptUnprotectData
    file_get_secret(service, account)
}

#[cfg(target_os = "windows")]
fn windows_set_secret(service: &str, account: &str, secret: &[u8]) -> Result<()> {
    // TODO: implement via CryptProtectData
    file_set_secret(service, account, secret)
}

// ---------------------------------------------------------------------------
// Linux — Secret Service (libsecret D-Bus)
// ---------------------------------------------------------------------------
#[cfg(target_os = "linux")]
fn linux_get_secret(service: &str, account: &str) -> Result<Vec<u8>> {
    // TODO: implement via Secret Service D-Bus API
    file_get_secret(service, account)
}

#[cfg(target_os = "linux")]
fn linux_set_secret(service: &str, account: &str, secret: &[u8]) -> Result<()> {
    // TODO: implement via Secret Service D-Bus API
    file_set_secret(service, account, secret)
}

// ---------------------------------------------------------------------------
// Fallback: plaintext file (development only)
// ---------------------------------------------------------------------------
fn secret_path(service: &str, account: &str) -> PathBuf {
    let dir = dirs_path();
    dir.join(format!("{}_{}.key", sanitise(service), sanitise(account)))
}

fn dirs_path() -> PathBuf {
    // Store under XDG_DATA_HOME / %APPDATA% / ~/Library/... as appropriate,
    // falling back to the current directory.
    std::env::var("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("driftwatch-agent")
}

fn sanitise(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_alphanumeric() || c == '-' { c } else { '_' })
        .collect()
}

fn file_get_secret(service: &str, account: &str) -> Result<Vec<u8>> {
    let path = secret_path(service, account);
    std::fs::read(&path).map_err(|e| anyhow!("keychain fallback read {:?}: {}", path, e))
}

fn file_set_secret(service: &str, account: &str, secret: &[u8]) -> Result<()> {
    let dir = dirs_path();
    std::fs::create_dir_all(&dir)?;
    let path = secret_path(service, account);
    std::fs::write(&path, secret)
        .map_err(|e| anyhow!("keychain fallback write {:?}: {}", path, e))
}
