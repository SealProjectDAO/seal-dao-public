//! Seal Wallet — Tauri backend with native Rust crypto.
//!
//! All cryptographic operations (ML-DSA signing, key derivation, address
//! generation) happen in Rust. The Svelte frontend only handles UI.
//!
//! Architecture:
//!   Svelte UI  →  Tauri IPC  →  Rust commands  →  seal-wallet / seal-crypto
//!
//! # Build
//! ```bash
//! cd apps/seal-wallet
//! cargo tauri dev    # Development (requires: cargo install tauri-cli)
//! cargo tauri build  # Release
//! ```

// When Tauri is available, uncomment:
// #![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

pub mod commands;

fn main() {
    // When Tauri is available:
    // tauri::Builder::default()
    //     .invoke_handler(tauri::generate_handler![
    //         commands::create_wallet,
    //         commands::import_wallet,
    //         commands::get_wallet_info,
    //         commands::export_mnemonic,
    //         commands::export_mnemonic_bip39,
    //         commands::sign_message,
    //         commands::verify_signature,
    //         commands::save_wallet,
    //         commands::load_wallet,
    //         commands::get_address,
    //         commands::get_balance,
    //     ])
    //     .run(tauri::generate_context!())
    //     .expect("error running Seal Wallet");

    // Standalone test: verify all commands work
    println!("Seal Wallet — native Rust crypto backend");
    println!();

    // Demo: create wallet
    let info = commands::create_wallet(true).unwrap();
    println!("Created wallet:");
    println!("  {}", info);

    // Demo: export mnemonic
    let mnemonic = commands::export_mnemonic().unwrap();
    println!("Mnemonic: {}", &mnemonic[..40]);
    println!("  (truncated for security)");

    // Demo: sign
    let sig = commands::sign_message("hello seal".into()).unwrap();
    println!("Signature: {}... ({} bytes)", &sig[..16], sig.len() / 2);

    // Demo: verify
    let valid = commands::verify_signature("hello seal".into(), sig).unwrap();
    println!("Verify: {}", valid);

    println!();
    println!("Install Tauri to run the full desktop app:");
    println!("  cargo install tauri-cli");
    println!("  cd apps/seal-wallet && cargo tauri dev");
}

#[cfg(test)]
mod tests {
    use super::commands;

    #[test]
    fn test_create_and_info() {
        let info = commands::create_wallet(true).unwrap();
        assert!(info.contains("sealt1"));

        let info2 = commands::get_wallet_info().unwrap();
        assert_eq!(info, info2);
    }

    #[test]
    fn test_import_from_mnemonic() {
        commands::create_wallet(true).unwrap();
        let mnemonic = commands::export_mnemonic().unwrap();
        let addr1 = commands::get_address().unwrap();

        // Import into fresh state
        let info = commands::import_wallet(mnemonic, true).unwrap();
        assert!(info.contains(&addr1));
    }

    #[test]
    fn test_sign_and_verify() {
        commands::create_wallet(true).unwrap();
        let sig = commands::sign_message("test data".into()).unwrap();
        assert!(!sig.is_empty());

        let valid = commands::verify_signature("test data".into(), sig.clone()).unwrap();
        assert!(valid);

        let invalid = commands::verify_signature("wrong data".into(), sig).unwrap();
        assert!(!invalid);
    }

    #[test]
    fn test_bip39_mnemonic() {
        commands::create_wallet(true).unwrap();
        let words = commands::export_mnemonic_bip39().unwrap();
        let word_count = words.split_whitespace().count();
        assert_eq!(word_count, 24, "BIP-39 should produce 24 words");
    }

    #[test]
    fn test_save_and_load() {
        commands::create_wallet(true).unwrap();
        let addr = commands::get_address().unwrap();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test_wallet.json");

        commands::save_wallet(
            path.to_str().unwrap().to_string(),
            "test_password".into(),
        )
        .unwrap();

        // Load into fresh state
        commands::load_wallet(
            path.to_str().unwrap().to_string(),
            "test_password".into(),
        )
        .unwrap();

        let addr2 = commands::get_address().unwrap();
        assert_eq!(addr, addr2);
    }
}
