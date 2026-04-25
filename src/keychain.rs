//! Platform keychain / credential storage abstraction.
//!
//! Backed by the OS credential store through the `keyring` crate:
//! - macOS Keychain
//! - Windows Credential Manager / DPAPI
//! - Linux Secret Service (libsecret-compatible providers)

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use keyring::Entry;

/// Retrieve a secret from the platform keychain.
pub fn get_secret(service: &str, account: &str) -> Result<Vec<u8>> {
    let entry = Entry::new(service, account)
        .map_err(|e| anyhow!("failed to open keyring entry for {service}/{account}: {e}"))?;
    let encoded = entry
        .get_password()
        .map_err(|e| anyhow!("failed to read keyring secret for {service}/{account}: {e}"))?;
    STANDARD
        .decode(encoded)
        .map_err(|e| anyhow!("failed to decode keyring payload for {service}/{account}: {e}"))
}

/// Store a secret in the platform keychain.
pub fn set_secret(service: &str, account: &str, secret: &[u8]) -> Result<()> {
    let entry = Entry::new(service, account)
        .map_err(|e| anyhow!("failed to open keyring entry for {service}/{account}: {e}"))?;
    let encoded = STANDARD.encode(secret);
    entry
        .set_password(&encoded)
        .map_err(|e| anyhow!("failed to write keyring secret for {service}/{account}: {e}"))
}
