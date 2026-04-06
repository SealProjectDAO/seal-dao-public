//! TEE (Trusted Execution Environment) attestation verification.
//!
//! Provides traits and stub implementations for verifying attestation quotes
//! from hardware-backed confidential computing platforms:
//! - Intel TDX (Trust Domain Extensions)
//! - AMD SEV-SNP (Secure Encrypted Virtualization — Secure Nested Paging)
//! - NVIDIA Confidential Computing
//!
//! These stubs always accept non-empty quotes. Real implementations will
//! perform cryptographic verification of the attestation evidence against
//! the platform vendor's root of trust.

use std::fmt;
use std::time::{Duration, Instant};

/// Default re-attestation interval: 5 minutes.
const DEFAULT_REATTESTATION_INTERVAL: Duration = Duration::from_secs(5 * 60);

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur during TEE attestation verification.
#[derive(Debug)]
pub enum TeeError {
    /// The quote bytes are malformed or empty.
    InvalidQuote,
    /// The attestation has exceeded its validity window.
    ExpiredAttestation,
    /// The platform is not supported by this verifier.
    UnsupportedPlatform,
    /// Verification failed with a descriptive reason.
    VerificationFailed(String),
}

impl fmt::Display for TeeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TeeError::InvalidQuote => write!(f, "invalid or empty attestation quote"),
            TeeError::ExpiredAttestation => write!(f, "attestation has expired"),
            TeeError::UnsupportedPlatform => write!(f, "unsupported TEE platform"),
            TeeError::VerificationFailed(reason) => {
                write!(f, "attestation verification failed: {}", reason)
            }
        }
    }
}

impl std::error::Error for TeeError {}

// ---------------------------------------------------------------------------
// Attestation result
// ---------------------------------------------------------------------------

/// The result of a successful attestation quote verification.
#[derive(Debug, Clone)]
pub struct AttestationResult {
    /// Whether the quote passed all verification checks.
    pub valid: bool,
    /// Name of the TEE platform that produced the quote.
    pub platform: String,
    /// Platform-specific measurement (e.g., MRTD for TDX, launch digest for SEV-SNP).
    pub measurement: Vec<u8>,
    /// Caller-supplied report data embedded in the quote.
    pub report_data: Vec<u8>,
    /// Unix timestamp (seconds) when the attestation was produced.
    pub timestamp: u64,
}

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Trait for TEE attestation verification.
///
/// Each implementation targets a specific hardware platform and knows how
/// to parse and cryptographically verify the attestation evidence produced
/// by that platform's firmware.
pub trait TeeAttestation {
    /// Human-readable name of the TEE platform (e.g., "Intel TDX").
    fn platform_name(&self) -> &str;

    /// Verify an attestation quote and return the parsed result.
    ///
    /// Returns `TeeError::InvalidQuote` if the quote is empty or malformed.
    fn verify_quote(&self, quote: &[u8]) -> Result<AttestationResult, TeeError>;

    /// Whether this instance currently holds a valid attestation.
    fn is_attested(&self) -> bool;

    /// Duration since the last successful attestation, or `None` if never attested.
    fn time_since_attestation(&self) -> Option<Duration>;
}

// ---------------------------------------------------------------------------
// Intel TDX — stub
// ---------------------------------------------------------------------------

/// Stub attestation verifier for Intel TDX (Trust Domain Extensions).
///
/// # Real implementation notes
///
/// A production verifier would:
/// 1. Parse the TDX DCAP (Data Center Attestation Primitives) quote structure.
/// 2. Verify the ECDSA signature over the quote body using the PCK
///    (Provisioning Certification Key) certificate.
/// 3. Walk the Intel signing chain: PCK -> Platform CA -> Root CA, checking
///    revocation via Intel PCS (Provisioning Certification Service).
/// 4. Validate measurement registers (MRTD, RTMR0-3) against expected values
///    to ensure the correct TD image was loaded.
/// 5. Check the QE (Quoting Enclave) identity against Intel's published
///    QE Identity structure.
/// 6. Verify that the report data field contains the expected nonce / binding.
pub struct IntelTdxAttestation {
    last_attestation: Option<Instant>,
}

impl IntelTdxAttestation {
    /// Create a new Intel TDX attestation verifier.
    pub fn new() -> Self {
        Self {
            last_attestation: None,
        }
    }
}

impl Default for IntelTdxAttestation {
    fn default() -> Self {
        Self::new()
    }
}

impl TeeAttestation for IntelTdxAttestation {
    fn platform_name(&self) -> &str {
        "Intel TDX"
    }

    fn verify_quote(&self, quote: &[u8]) -> Result<AttestationResult, TeeError> {
        if quote.is_empty() {
            return Err(TeeError::InvalidQuote);
        }

        // Stub: accept any non-empty quote as valid.
        // A real implementation would perform full DCAP verification here.
        Ok(AttestationResult {
            valid: true,
            platform: "Intel TDX".to_string(),
            measurement: quote.to_vec(),
            report_data: quote.to_vec(),
            timestamp: current_unix_timestamp(),
        })
    }

    fn is_attested(&self) -> bool {
        self.last_attestation.is_some()
    }

    fn time_since_attestation(&self) -> Option<Duration> {
        self.last_attestation.map(|t| t.elapsed())
    }
}

// ---------------------------------------------------------------------------
// AMD SEV-SNP — stub
// ---------------------------------------------------------------------------

/// Stub attestation verifier for AMD SEV-SNP.
///
/// # Real implementation notes
///
/// A production verifier would:
/// 1. Parse the SEV-SNP attestation report (MSG_REPORT_RSP).
/// 2. Verify the report signature using the VCEK (Versioned Chip Endorsement
///    Key) public key obtained from the AMD Key Distribution Service (KDS).
/// 3. Validate the VCEK certificate chain: VCEK -> ASK (AMD SEV Key) ->
///    ARK (AMD Root Key).
/// 4. Compare the `MEASUREMENT` field (launch digest) against expected values
///    to ensure the correct guest image was loaded.
/// 5. Check `POLICY` bits (e.g., debug disabled, migration disabled).
/// 6. Verify `REPORT_DATA` contains the expected nonce / channel binding.
/// 7. Optionally validate `HOST_DATA`, `ID_KEY_DIGEST`, and TCB version
///    against minimum required levels.
pub struct AmdSevSnpAttestation {
    last_attestation: Option<Instant>,
}

impl AmdSevSnpAttestation {
    /// Create a new AMD SEV-SNP attestation verifier.
    pub fn new() -> Self {
        Self {
            last_attestation: None,
        }
    }
}

impl Default for AmdSevSnpAttestation {
    fn default() -> Self {
        Self::new()
    }
}

impl TeeAttestation for AmdSevSnpAttestation {
    fn platform_name(&self) -> &str {
        "AMD SEV-SNP"
    }

    fn verify_quote(&self, quote: &[u8]) -> Result<AttestationResult, TeeError> {
        if quote.is_empty() {
            return Err(TeeError::InvalidQuote);
        }

        // Stub: accept any non-empty quote as valid.
        // A real implementation would perform full SEV-SNP report verification.
        Ok(AttestationResult {
            valid: true,
            platform: "AMD SEV-SNP".to_string(),
            measurement: quote.to_vec(),
            report_data: quote.to_vec(),
            timestamp: current_unix_timestamp(),
        })
    }

    fn is_attested(&self) -> bool {
        self.last_attestation.is_some()
    }

    fn time_since_attestation(&self) -> Option<Duration> {
        self.last_attestation.map(|t| t.elapsed())
    }
}

// ---------------------------------------------------------------------------
// NVIDIA Confidential Computing — stub
// ---------------------------------------------------------------------------

/// Stub attestation verifier for NVIDIA Confidential Computing.
///
/// # Real implementation notes
///
/// A production verifier would:
/// 1. Retrieve the GPU attestation evidence via the NVIDIA Attestation SDK
///    (nvml or NRAS API).
/// 2. Verify the attestation certificate chain rooted in NVIDIA's device
///    root certificate.
/// 3. Validate the GPU firmware measurements against NVIDIA's Reference
///    Integrity Manifest (RIM).
/// 4. Confirm the Confidential Computing mode is enabled (CC-on) and that
///    the GPU memory encryption is active (AES-256 with HBM encryption).
/// 5. Verify the nonce / report data for freshness and channel binding.
/// 6. Optionally cross-check the CPU TEE attestation (TDX or SEV-SNP) to
///    ensure the GPU is attached to an attested confidential VM.
pub struct NvidiaConfidentialCompute {
    last_attestation: Option<Instant>,
}

impl NvidiaConfidentialCompute {
    /// Create a new NVIDIA Confidential Computing attestation verifier.
    pub fn new() -> Self {
        Self {
            last_attestation: None,
        }
    }
}

impl Default for NvidiaConfidentialCompute {
    fn default() -> Self {
        Self::new()
    }
}

impl TeeAttestation for NvidiaConfidentialCompute {
    fn platform_name(&self) -> &str {
        "NVIDIA CC"
    }

    fn verify_quote(&self, quote: &[u8]) -> Result<AttestationResult, TeeError> {
        if quote.is_empty() {
            return Err(TeeError::InvalidQuote);
        }

        // Stub: accept any non-empty quote as valid.
        // A real implementation would perform NVIDIA CC attestation verification.
        Ok(AttestationResult {
            valid: true,
            platform: "NVIDIA CC".to_string(),
            measurement: quote.to_vec(),
            report_data: quote.to_vec(),
            timestamp: current_unix_timestamp(),
        })
    }

    fn is_attested(&self) -> bool {
        self.last_attestation.is_some()
    }

    fn time_since_attestation(&self) -> Option<Duration> {
        self.last_attestation.map(|t| t.elapsed())
    }
}

// ---------------------------------------------------------------------------
// Re-attestation timer
// ---------------------------------------------------------------------------

/// Tracks when the last attestation occurred and whether re-attestation is due.
///
/// Confidential computing best practice requires periodic re-attestation to
/// detect platform state changes (e.g., microcode updates, firmware patches)
/// that may invalidate the original measurement.
pub struct ReattestationTimer {
    /// Interval between required re-attestations.
    interval: Duration,
    /// Instant of the last successful attestation, if any.
    last_attestation: Option<Instant>,
}

impl ReattestationTimer {
    /// Create a new timer with the default 5-minute interval.
    pub fn new() -> Self {
        Self {
            interval: DEFAULT_REATTESTATION_INTERVAL,
            last_attestation: None,
        }
    }

    /// Create a new timer with a custom interval.
    pub fn with_interval(interval: Duration) -> Self {
        Self {
            interval,
            last_attestation: None,
        }
    }

    /// Record that a successful attestation just happened.
    pub fn record_attestation(&mut self) {
        self.last_attestation = Some(Instant::now());
    }

    /// Record an attestation at a specific instant (useful for testing).
    pub fn record_attestation_at(&mut self, when: Instant) {
        self.last_attestation = Some(when);
    }

    /// Check whether re-attestation is needed.
    ///
    /// Returns `true` if:
    /// - No attestation has ever been recorded, or
    /// - The time since the last attestation exceeds the configured interval.
    pub fn needs_reattestation(&self) -> bool {
        match self.last_attestation {
            None => true,
            Some(last) => last.elapsed() >= self.interval,
        }
    }

    /// Duration since the last attestation, or `None` if never attested.
    pub fn time_since_last(&self) -> Option<Duration> {
        self.last_attestation.map(|t| t.elapsed())
    }

    /// The configured re-attestation interval.
    pub fn interval(&self) -> Duration {
        self.interval
    }
}

impl Default for ReattestationTimer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Return the current Unix timestamp in seconds.
///
/// Falls back to 0 if the system clock is before the Unix epoch.
fn current_unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Intel TDX --

    #[test]
    fn tdx_verify_valid_quote() {
        let verifier = IntelTdxAttestation::new();
        let quote = b"fake-tdx-quote-data";
        let result = verifier.verify_quote(quote).unwrap();
        assert!(result.valid);
        assert_eq!(result.platform, "Intel TDX");
        assert_eq!(result.measurement, quote.to_vec());
        assert_eq!(result.report_data, quote.to_vec());
        assert!(result.timestamp > 0);
    }

    #[test]
    fn tdx_verify_empty_quote_rejected() {
        let verifier = IntelTdxAttestation::new();
        let result = verifier.verify_quote(b"");
        assert!(result.is_err());
        match result {
            Err(TeeError::InvalidQuote) => {} // expected
            other => panic!("expected InvalidQuote, got {:?}", other),
        }
    }

    #[test]
    fn tdx_platform_name() {
        let verifier = IntelTdxAttestation::new();
        assert_eq!(verifier.platform_name(), "Intel TDX");
    }

    #[test]
    fn tdx_not_attested_initially() {
        let verifier = IntelTdxAttestation::new();
        assert!(!verifier.is_attested());
        assert!(verifier.time_since_attestation().is_none());
    }

    // -- AMD SEV-SNP --

    #[test]
    fn sevsnp_verify_valid_quote() {
        let verifier = AmdSevSnpAttestation::new();
        let quote = b"fake-sevsnp-report";
        let result = verifier.verify_quote(quote).unwrap();
        assert!(result.valid);
        assert_eq!(result.platform, "AMD SEV-SNP");
        assert_eq!(result.measurement, quote.to_vec());
    }

    #[test]
    fn sevsnp_verify_empty_quote_rejected() {
        let verifier = AmdSevSnpAttestation::new();
        let result = verifier.verify_quote(b"");
        assert!(result.is_err());
        match result {
            Err(TeeError::InvalidQuote) => {}
            other => panic!("expected InvalidQuote, got {:?}", other),
        }
    }

    #[test]
    fn sevsnp_platform_name() {
        let verifier = AmdSevSnpAttestation::new();
        assert_eq!(verifier.platform_name(), "AMD SEV-SNP");
    }

    #[test]
    fn sevsnp_not_attested_initially() {
        let verifier = AmdSevSnpAttestation::new();
        assert!(!verifier.is_attested());
        assert!(verifier.time_since_attestation().is_none());
    }

    // -- NVIDIA CC --

    #[test]
    fn nvidia_verify_valid_quote() {
        let verifier = NvidiaConfidentialCompute::new();
        let quote = b"fake-nvidia-attestation";
        let result = verifier.verify_quote(quote).unwrap();
        assert!(result.valid);
        assert_eq!(result.platform, "NVIDIA CC");
        assert_eq!(result.measurement, quote.to_vec());
    }

    #[test]
    fn nvidia_verify_empty_quote_rejected() {
        let verifier = NvidiaConfidentialCompute::new();
        let result = verifier.verify_quote(b"");
        assert!(result.is_err());
        match result {
            Err(TeeError::InvalidQuote) => {}
            other => panic!("expected InvalidQuote, got {:?}", other),
        }
    }

    #[test]
    fn nvidia_platform_name() {
        let verifier = NvidiaConfidentialCompute::new();
        assert_eq!(verifier.platform_name(), "NVIDIA CC");
    }

    #[test]
    fn nvidia_not_attested_initially() {
        let verifier = NvidiaConfidentialCompute::new();
        assert!(!verifier.is_attested());
        assert!(verifier.time_since_attestation().is_none());
    }

    // -- ReattestationTimer --

    #[test]
    fn timer_needs_reattestation_when_never_attested() {
        let timer = ReattestationTimer::new();
        assert!(timer.needs_reattestation());
        assert!(timer.time_since_last().is_none());
    }

    #[test]
    fn timer_does_not_need_reattestation_just_after_recording() {
        let mut timer = ReattestationTimer::new();
        timer.record_attestation();
        assert!(!timer.needs_reattestation());
        assert!(timer.time_since_last().is_some());
    }

    #[test]
    fn timer_needs_reattestation_after_interval_expires() {
        let mut timer = ReattestationTimer::with_interval(Duration::from_secs(1));
        // Record attestation at a point far enough in the past.
        let past = Instant::now() - Duration::from_secs(2);
        timer.record_attestation_at(past);
        assert!(timer.needs_reattestation());
    }

    #[test]
    fn timer_does_not_need_reattestation_within_interval() {
        let mut timer = ReattestationTimer::with_interval(Duration::from_secs(300));
        timer.record_attestation();
        assert!(!timer.needs_reattestation());
    }

    #[test]
    fn timer_default_interval_is_five_minutes() {
        let timer = ReattestationTimer::new();
        assert_eq!(timer.interval(), Duration::from_secs(300));
    }

    #[test]
    fn timer_custom_interval() {
        let timer = ReattestationTimer::with_interval(Duration::from_secs(60));
        assert_eq!(timer.interval(), Duration::from_secs(60));
    }

    // -- TeeError Display --

    #[test]
    fn error_display_messages() {
        assert_eq!(
            TeeError::InvalidQuote.to_string(),
            "invalid or empty attestation quote"
        );
        assert_eq!(
            TeeError::ExpiredAttestation.to_string(),
            "attestation has expired"
        );
        assert_eq!(
            TeeError::UnsupportedPlatform.to_string(),
            "unsupported TEE platform"
        );
        assert_eq!(
            TeeError::VerificationFailed("bad sig".to_string()).to_string(),
            "attestation verification failed: bad sig"
        );
    }

    // -- Trait object usage --

    #[test]
    fn trait_object_dispatch() {
        let verifiers: Vec<Box<dyn TeeAttestation>> = vec![
            Box::new(IntelTdxAttestation::new()),
            Box::new(AmdSevSnpAttestation::new()),
            Box::new(NvidiaConfidentialCompute::new()),
        ];

        for verifier in &verifiers {
            let result = verifier.verify_quote(b"test-quote").unwrap();
            assert!(result.valid);
            assert!(!verifier.is_attested());
        }
    }
}
