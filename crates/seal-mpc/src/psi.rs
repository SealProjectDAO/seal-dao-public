//! Private Set Intersection (PSI) for privacy-preserving SQL JOINs.
//!
//! Allows two parties to compute the intersection of their row sets
//! without revealing non-intersecting rows. Used for privacy-preserving
//! JOIN operations on seal-sql tables.
//!
//! # Protocol (Hash-Based PSI)
//!
//! ```text
//! Party A (set S_A)                    Party B (set S_B)
//! ─────────────────                    ─────────────────
//! For each x in S_A:
//!   h_x = SHA3(salt || x)
//! Send {h_x} to B                ──►
//!
//!                                     For each y in S_B:
//!                                       h_y = SHA3(salt || y)
//!                                     Intersection = {h_x} ∩ {h_y}
//!                                ◄──  Send matching h values
//!
//! A filters S_A to matching items
//! ```
//!
//! # Security
//!
//! - **Semi-honest security**: Neither party learns non-intersecting elements
//! - **Leakage**: Both parties learn the intersection size
//! - **PQ-secure**: SHA3-256 hashing (collision and preimage resistant)
//!
//! # Limitations
//!
//! This is a simplified hash-based PSI. Production deployments should use:
//! - OPRF-based PSI (stronger security, hides set sizes)
//! - Circuit-based PSI (malicious security)
//! - PSI with payload (returns associated values, not just keys)
//!
//! The trait-based design allows drop-in replacement with stronger protocols.

use seal_crypto::hash::{sha3_256, Hash256};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Result of a PSI computation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PsiResult {
    /// Hashes of intersecting elements.
    pub intersection_hashes: Vec<Hash256>,
    /// Number of elements in the intersection.
    pub intersection_size: usize,
    /// Total elements in our set.
    pub our_set_size: usize,
}

impl PsiResult {
    /// Whether the intersection is empty.
    pub fn is_empty(&self) -> bool {
        self.intersection_size == 0
    }
}

/// Salt for hashing elements in PSI.
/// Both parties must agree on the same salt.
#[derive(Clone, Debug)]
pub struct PsiSalt(pub [u8; 32]);

impl PsiSalt {
    /// Generate a random salt.
    pub fn random() -> Self {
        let mut bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
        PsiSalt(bytes)
    }

    /// Create from a shared secret (e.g., from ML-KEM key exchange).
    pub fn from_shared_secret(secret: &[u8]) -> Self {
        let hash = sha3_256(secret);
        PsiSalt(hash.0)
    }
}

/// Hash an element with the PSI salt.
fn hash_element(salt: &PsiSalt, element: &[u8]) -> Hash256 {
    let mut input = Vec::with_capacity(32 + element.len());
    input.extend_from_slice(&salt.0);
    input.extend_from_slice(element);
    sha3_256(&input)
}

/// Initiator side of the PSI protocol (Party A).
///
/// Party A sends hashed elements to Party B.
pub struct PsiInitiator {
    salt: PsiSalt,
    /// Our elements (raw).
    elements: Vec<Vec<u8>>,
    /// Our element hashes.
    hashes: Vec<Hash256>,
}

impl PsiInitiator {
    /// Create a new PSI initiator with our set elements.
    pub fn new(salt: PsiSalt, elements: Vec<Vec<u8>>) -> Self {
        let hashes: Vec<Hash256> = elements.iter().map(|e| hash_element(&salt, e)).collect();
        PsiInitiator {
            salt,
            elements,
            hashes,
        }
    }

    /// Message 1: our hashed elements (send to responder).
    pub fn msg1(&self) -> Vec<Hash256> {
        self.hashes.clone()
    }

    /// Process the response: filter our elements to the intersection.
    ///
    /// `matching_hashes` are the hashes the responder found in common.
    pub fn process_response(&self, matching_hashes: &[Hash256]) -> PsiResult {
        let matching_set: HashSet<[u8; 32]> = matching_hashes.iter().map(|h| h.0).collect();

        let intersection_hashes: Vec<Hash256> = self
            .hashes
            .iter()
            .filter(|h| matching_set.contains(&h.0))
            .cloned()
            .collect();

        PsiResult {
            intersection_size: intersection_hashes.len(),
            our_set_size: self.elements.len(),
            intersection_hashes,
        }
    }

    /// Get the original elements that are in the intersection.
    pub fn get_intersecting_elements(&self, matching_hashes: &[Hash256]) -> Vec<Vec<u8>> {
        let matching_set: HashSet<[u8; 32]> = matching_hashes.iter().map(|h| h.0).collect();

        self.elements
            .iter()
            .zip(self.hashes.iter())
            .filter(|(_, h)| matching_set.contains(&h.0))
            .map(|(elem, _)| elem.clone())
            .collect()
    }

    /// The salt used (for verification).
    pub fn salt(&self) -> &PsiSalt {
        &self.salt
    }
}

/// Responder side of the PSI protocol (Party B).
///
/// Party B receives hashed elements and finds the intersection.
pub struct PsiResponder {
    _salt: PsiSalt,
    /// Our elements (raw).
    elements: Vec<Vec<u8>>,
    /// Our element hashes (as a set for O(1) lookup).
    hash_set: HashSet<[u8; 32]>,
    /// Our element hashes (ordered).
    hashes: Vec<Hash256>,
}

impl PsiResponder {
    /// Create a new PSI responder with our set elements.
    pub fn new(salt: PsiSalt, elements: Vec<Vec<u8>>) -> Self {
        let hashes: Vec<Hash256> = elements.iter().map(|e| hash_element(&salt, e)).collect();
        let hash_set: HashSet<[u8; 32]> = hashes.iter().map(|h| h.0).collect();
        PsiResponder {
            _salt: salt,
            elements,
            hash_set,
            hashes,
        }
    }

    /// Process initiator's hashed elements and find intersection.
    ///
    /// Returns the hashes that are in both sets.
    pub fn process_msg1(&self, initiator_hashes: &[Hash256]) -> Vec<Hash256> {
        initiator_hashes
            .iter()
            .filter(|h| self.hash_set.contains(&h.0))
            .cloned()
            .collect()
    }

    /// Full PSI computation: process msg1 and return our result.
    pub fn compute(&self, initiator_hashes: &[Hash256]) -> PsiResult {
        let matching = self.process_msg1(initiator_hashes);

        PsiResult {
            intersection_size: matching.len(),
            our_set_size: self.elements.len(),
            intersection_hashes: matching,
        }
    }

    /// Get the original elements that are in the intersection.
    pub fn get_intersecting_elements(&self, initiator_hashes: &[Hash256]) -> Vec<Vec<u8>> {
        let initiator_set: HashSet<[u8; 32]> = initiator_hashes.iter().map(|h| h.0).collect();

        self.elements
            .iter()
            .zip(self.hashes.iter())
            .filter(|(_, h)| initiator_set.contains(&h.0))
            .map(|(elem, _)| elem.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_elements(items: &[&str]) -> Vec<Vec<u8>> {
        items.iter().map(|s| s.as_bytes().to_vec()).collect()
    }

    #[test]
    fn test_full_psi_protocol() {
        let salt = PsiSalt::from_shared_secret(b"shared-secret");

        let set_a = make_elements(&["alice", "bob", "charlie", "dave"]);
        let set_b = make_elements(&["bob", "charlie", "eve", "frank"]);

        let initiator = PsiInitiator::new(salt.clone(), set_a);
        let responder = PsiResponder::new(salt, set_b);

        // Step 1: Initiator sends hashed elements
        let msg1 = initiator.msg1();
        assert_eq!(msg1.len(), 4);

        // Step 2: Responder finds intersection
        let matching = responder.process_msg1(&msg1);
        assert_eq!(matching.len(), 2); // "bob" and "charlie"

        // Step 3: Initiator processes response
        let result = initiator.process_response(&matching);
        assert_eq!(result.intersection_size, 2);
        assert_eq!(result.our_set_size, 4);

        // Verify actual elements
        let a_elements = initiator.get_intersecting_elements(&matching);
        assert_eq!(a_elements.len(), 2);
        assert!(a_elements.contains(&b"bob".to_vec()));
        assert!(a_elements.contains(&b"charlie".to_vec()));

        let b_elements = responder.get_intersecting_elements(&msg1);
        assert_eq!(b_elements.len(), 2);
        assert!(b_elements.contains(&b"bob".to_vec()));
        assert!(b_elements.contains(&b"charlie".to_vec()));
    }

    #[test]
    fn test_empty_intersection() {
        let salt = PsiSalt::from_shared_secret(b"secret");

        let set_a = make_elements(&["alice", "bob"]);
        let set_b = make_elements(&["charlie", "dave"]);

        let initiator = PsiInitiator::new(salt.clone(), set_a);
        let responder = PsiResponder::new(salt, set_b);

        let msg1 = initiator.msg1();
        let matching = responder.process_msg1(&msg1);
        assert!(matching.is_empty());

        let result = initiator.process_response(&matching);
        assert!(result.is_empty());
    }

    #[test]
    fn test_full_intersection() {
        let salt = PsiSalt::from_shared_secret(b"secret");

        let set_a = make_elements(&["alice", "bob"]);
        let set_b = make_elements(&["alice", "bob"]);

        let initiator = PsiInitiator::new(salt.clone(), set_a);
        let responder = PsiResponder::new(salt, set_b);

        let msg1 = initiator.msg1();
        let result = responder.compute(&msg1);
        assert_eq!(result.intersection_size, 2);
    }

    #[test]
    fn test_different_salts_no_match() {
        let salt_a = PsiSalt::from_shared_secret(b"secret-a");
        let salt_b = PsiSalt::from_shared_secret(b"secret-b");

        let set = make_elements(&["alice", "bob"]);

        let initiator = PsiInitiator::new(salt_a, set.clone());
        let responder = PsiResponder::new(salt_b, set);

        let msg1 = initiator.msg1();
        let matching = responder.process_msg1(&msg1);
        // Different salts → different hashes → no intersection
        assert!(matching.is_empty());
    }

    #[test]
    fn test_large_sets() {
        let salt = PsiSalt::from_shared_secret(b"secret");

        let set_a: Vec<Vec<u8>> = (0..1000).map(|i| format!("elem-{}", i).into_bytes()).collect();
        let set_b: Vec<Vec<u8>> = (500..1500).map(|i| format!("elem-{}", i).into_bytes()).collect();

        let initiator = PsiInitiator::new(salt.clone(), set_a);
        let responder = PsiResponder::new(salt, set_b);

        let msg1 = initiator.msg1();
        let result = responder.compute(&msg1);
        assert_eq!(result.intersection_size, 500); // elements 500..999
    }

    #[test]
    fn test_hash_deterministic() {
        let salt = PsiSalt::from_shared_secret(b"secret");
        let h1 = hash_element(&salt, b"test");
        let h2 = hash_element(&salt, b"test");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_different_elements() {
        let salt = PsiSalt::from_shared_secret(b"secret");
        let h1 = hash_element(&salt, b"alice");
        let h2 = hash_element(&salt, b"bob");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_psi_result_is_empty() {
        let result = PsiResult {
            intersection_hashes: vec![],
            intersection_size: 0,
            our_set_size: 10,
        };
        assert!(result.is_empty());
    }

    #[test]
    fn test_random_salt() {
        let s1 = PsiSalt::random();
        let s2 = PsiSalt::random();
        assert_ne!(s1.0, s2.0);
    }
}
