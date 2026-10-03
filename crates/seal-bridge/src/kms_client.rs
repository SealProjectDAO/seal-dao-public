//! KMS sidecar client — implements `CommitteeSigner` / `RingtailSigner`
//! traits so `BridgeManager` can delegate signing to a Unix-socket KMS.
//!
//! The KMS sidecar receives withdrawal context (chain, address, amount,
//! nonce), builds the HMAC payload internally, and returns the signature.
//! The raw key never leaves the sidecar.

use crate::keysource::CommitteeSigner;
use seal_kms_client::api::KmsClient;
use std::path::PathBuf;
use std::sync::Arc;

/// Adaptor that implements `CommitteeSigner` by talking to the KMS
/// sidecar over a Unix domain socket.
pub struct KmsCommitteeSigner {
    client: Arc<KmsClient>,
    _socket_path: PathBuf,
}

impl KmsCommitteeSigner {
    /// Connect to the KMS sidecar.
    pub async fn connect(socket_path: PathBuf) -> Result<Self, String> {
        let client = KmsClient::connect(&socket_path)
            .await
            .map_err(|e| format!("KMS connect failed: {e}"))?;
        Ok(Self {
            client: Arc::new(client),
            _socket_path: socket_path,
        })
    }
}

impl CommitteeSigner for KmsCommitteeSigner {
    fn sign_committee(
        &self,
        dest_chain: &crate::types::Chain,
        dest_address: &str,
        amount: u64,
        nonce: u64,
    ) -> Result<String, String> {
        // Use the same payload builder as the local HMAC path to
        // guarantee signature compatibility between KMS and legacy.
        let payload = crate::bridge::build_unlock_payload(
            dest_chain, dest_address, amount, nonce,
        );
        let handle = tokio::runtime::Handle::try_current()
            .map_err(|_| "no tokio runtime available for KMS call".to_string())?;
        handle
            .block_on(self.client.sign_committee(&hex::encode(payload), nonce))
            .map_err(|e| format!("KMS sign_committee failed: {e}"))
    }
}

/// Adaptor that implements `RingtailSigner` by talking to the KMS
/// sidecar over a Unix domain socket.
///
/// **Note:** The KMS sidecar's `sign_ringtail` endpoint is currently
/// a placeholder (returns the stored ringtail SK hex). A real
/// implementation requires integrating the Ringtail threshold signing
/// into the sidecar's `cmd_sign_ringtail`.
#[cfg(feature = "ringtail-singleton")]
pub struct KmsRingtailSigner {
    client: Arc<KmsClient>,
    _socket_path: PathBuf,
}

#[cfg(feature = "ringtail-singleton")]
impl KmsRingtailSigner {
    /// Connect to the KMS sidecar.
    pub async fn connect(socket_path: PathBuf) -> Result<Self, String> {
        let client = KmsClient::connect(&socket_path)
            .await
            .map_err(|e| format!("KMS connect failed: {e}"))?;
        Ok(Self {
            client: Arc::new(client),
            _socket_path: socket_path,
        })
    }
}

#[cfg(feature = "ringtail-singleton")]
impl crate::keysource::RingtailSigner for KmsRingtailSigner {
    fn sign_ringtail(
        &self,
        dest_chain: &crate::types::Chain,
        dest_address: &str,
        amount: u64,
        nonce: u64,
    ) -> Result<String, String> {
        let payload = crate::bridge::build_unlock_payload(
            dest_chain, dest_address, amount, nonce,
        );
        let handle = tokio::runtime::Handle::try_current()
            .map_err(|_| "no tokio runtime available for KMS call".to_string())?;
        handle
            .block_on(self.client.sign_ringtail(&hex::encode(payload)))
            .map_err(|e| format!("KMS sign_ringtail failed: {e}"))
    }
}
