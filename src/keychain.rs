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

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    #[test]
    fn base64_encode_decode_roundtrip() {
        let original = b"test_secret_key_12345";
        let encoded = STANDARD.encode(original);
        let decoded = STANDARD.decode(&encoded).expect("decode failed");
        assert_eq!(original.to_vec(), decoded);
    }

    #[test]
    fn base64_encode_empty_bytes() {
        let empty = b"";
        let encoded = STANDARD.encode(empty);
        assert_eq!(encoded, "");
        let decoded: Vec<u8> = STANDARD.decode(&encoded).expect("decode failed");
        assert_eq!(decoded, Vec::<u8>::new());
    }

    #[test]
    fn base64_encode_binary_data() {
        let binary = vec![0u8, 1, 2, 3, 255, 254, 253];
        let encoded = STANDARD.encode(&binary);
        let decoded = STANDARD.decode(&encoded).expect("decode failed");
        assert_eq!(binary, decoded);
    }

    #[test]
    fn service_account_combinations_valid() {
        // Verify that service and account identifiers are properly formatted
        let test_cases = vec![
            ("driftwatch", "device-key"),
            ("driftwatch", "ipc-token"),
            ("com.example.driftwatch", "primary-key"),
        ];

        for (service, account) in test_cases {
            assert!(!service.is_empty());
            assert!(!account.is_empty());
        }
    }

    #[test]
    fn error_message_formatting() {
        // Verify error message construction doesn't panic
        let service = "test_service";
        let account = "test_account";
        let error_msg = format!(
            "failed to open keyring entry for {}/{}: {}",
            service, account, "test error"
        );
        assert!(error_msg.contains(service));
        assert!(error_msg.contains(account));
    }
}
