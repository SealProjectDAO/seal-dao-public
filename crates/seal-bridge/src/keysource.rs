//! Key-source adapter traits (P8/§4.4 mainnet gate).
//!
//! Pre-P8 the committee MAC key and Ringtail keypair were loaded as
//! raw bytes from disk via CLI flags. That's fine for testnet but
//! mainnet operators want the option to source secret material from
//! a hardware HSM, AWS KMS, GCP Cloud KMS, or HashiCorp Vault
//! without forking seal-node. This module defines the trait shapes
//! so the rest of the codebase calls a `dyn CommitteeKeySource` /
//! `dyn RingtailKeySource` instead of mishandling `Vec<u8>` blobs
//! at every load site.
//!
//! Testnet default: `FileKeySource` reads from a JSON file. Mainnet
//! HSM/KMS impls are out of scope for this commit — they're
//! drop-in: `impl CommitteeKeySource for AwsKmsClient { ... }` and
//! seal-node main picks them up via a single `--bridge-kms-config
//! <path>` swap.

use std::path::{Path, PathBuf};

/// Source for the 32-byte committee MAC key used by the host's
/// HMAC committee-of-1 unlock path.
pub trait CommitteeKeySource: Send + Sync {
    /// Read the current committee MAC key. Implementations MAY
    /// cache (FileKeySource does); rotation-aware impls re-read on
    /// each call so a council-gated rotate-key call propagates
    /// without restart.
    fn read_committee_mac(&self) -> Result<[u8; 32], String>;
}

/// Source for the Ringtail (PublicParams + collapsed sk) keypair
/// used by the multi-validator threshold-signing path.
#[cfg(feature = "ringtail-singleton")]
pub trait RingtailKeySource: Send + Sync {
    /// Read the validator's Ringtail keypair.
    fn read_keypair(&self) -> Result<crate::ringtail::RingtailKeypair, String>;
}

/// File-backed key source — the testnet default + the
/// backwards-compatible path for operators not running an HSM.
/// Holds paths only; reads happen lazily on each call so a
/// rotation that overwrites the file is picked up next access.
pub struct FileKeySource {
    /// Path to the 32-byte hex-encoded committee MAC key (one
    /// 64-char hex string, optionally with a trailing newline).
    /// `None` if the committee MAC path isn't wired (Ringtail-only
    /// nodes).
    pub committee_mac_path: Option<PathBuf>,
    /// Path to the Ringtail keypair JSON (the format the
    /// `bridge-ringtail-keygen` example produces). `None` if the
    /// node only does HMAC committee-of-1.
    pub ringtail_keypair_path: Option<PathBuf>,
}

impl FileKeySource {
    /// Build a file-backed key source. Either path may be `None`
    /// when that primitive isn't in use.
    pub fn new(
        committee_mac_path: Option<PathBuf>,
        ringtail_keypair_path: Option<PathBuf>,
    ) -> Self {
        Self {
            committee_mac_path,
            ringtail_keypair_path,
        }
    }

    /// Convenience constructor for a node that only uses the HMAC
    /// committee-of-1 path.
    pub fn hmac_only(committee_mac_path: PathBuf) -> Self {
        Self {
            committee_mac_path: Some(committee_mac_path),
            ringtail_keypair_path: None,
        }
    }

    /// Helper used by `CommitteeKeySource::read_committee_mac` and
    /// by tests. Decodes a 64-char hex file into 32 bytes; trims
    /// surrounding whitespace so a file produced by `echo` works
    /// without any extra ceremony.
    fn read_mac_from(path: &Path) -> Result<[u8; 32], String> {
        let txt =
            std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let trimmed = txt.trim();
        let bytes =
            hex::decode(trimmed).map_err(|e| format!("hex decode {}: {e}", path.display()))?;
        if bytes.len() != 32 {
            return Err(format!(
                "{}: expected 32 bytes (64 hex chars), got {}",
                path.display(),
                bytes.len()
            ));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

impl CommitteeKeySource for FileKeySource {
    fn read_committee_mac(&self) -> Result<[u8; 32], String> {
        let path = self
            .committee_mac_path
            .as_ref()
            .ok_or_else(|| "FileKeySource has no committee_mac_path configured".to_string())?;
        Self::read_mac_from(path)
    }
}

#[cfg(feature = "ringtail-singleton")]
impl RingtailKeySource for FileKeySource {
    fn read_keypair(&self) -> Result<crate::ringtail::RingtailKeypair, String> {
        let path = self
            .ringtail_keypair_path
            .as_ref()
            .ok_or_else(|| "FileKeySource has no ringtail_keypair_path configured".to_string())?;
        crate::ringtail::RingtailKeypair::load_from_file(path)
            .map_err(|e| format!("ringtail keypair load {}: {e}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_tmp_hex(name: &str, hex_str: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("seal-bridge-keysource-test-{name}.hex"));
        std::fs::write(&p, hex_str).unwrap();
        p
    }

    #[test]
    fn file_key_source_reads_committee_mac() {
        let path = write_tmp_hex(
            "ok",
            "1111111111111111111111111111111111111111111111111111111111111111\n",
        );
        let src = FileKeySource::hmac_only(path);
        let key = src.read_committee_mac().expect("read ok");
        assert_eq!(key, [0x11u8; 32]);
    }

    #[test]
    fn file_key_source_rejects_short_hex() {
        let path = write_tmp_hex("short", "1111");
        let src = FileKeySource::hmac_only(path);
        let err = src.read_committee_mac().expect_err("short hex");
        assert!(err.contains("expected 32 bytes"), "err: {err}");
    }

    #[test]
    fn file_key_source_without_mac_path_errors_clearly() {
        let src = FileKeySource::new(None, None);
        let err = src.read_committee_mac().expect_err("no path");
        assert!(err.contains("no committee_mac_path"), "err: {err}");
    }
}
