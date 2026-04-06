//! AI inference request/response types for TEE execution.

use serde::{Deserialize, Serialize};

/// An inference request to a TEE node.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InferenceRequest {
    /// Unique request ID.
    pub id: String,
    /// Model name (e.g., "llama-3-8b", "mistral-7b").
    pub model: String,
    /// Input prompt.
    pub input: String,
    /// Maximum output tokens.
    pub max_tokens: u32,
    /// Requester's SEAL address.
    pub requester: String,
}

/// An inference result from a TEE node.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InferenceResult {
    /// Request ID this responds to.
    pub request_id: String,
    /// Generated output text.
    pub output: String,
    /// Number of input tokens processed.
    pub input_tokens: u32,
    /// Number of output tokens generated.
    pub output_tokens: u32,
    /// TEE node that executed the inference.
    pub node_id: String,
    /// TEE attestation hash (proof of genuine execution).
    pub attestation_hash: Vec<u8>,
}

impl InferenceResult {
    /// Compute cost in micro-SEAL using the pricing formula:
    /// cost = input_tokens + (4 × output_tokens)
    /// (Same weighting as Secret Network, SPEC.md §10.2)
    pub fn compute_cost(&self, price_per_unit: u64) -> u64 {
        let units = self.input_tokens as u64 + 4 * self.output_tokens as u64;
        units.saturating_mul(price_per_unit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_cost() {
        let result = InferenceResult {
            request_id: "req_1".into(),
            output: "Hello world".into(),
            input_tokens: 100,
            output_tokens: 50,
            node_id: "node_1".into(),
            attestation_hash: vec![],
        };

        // 100 + 4*50 = 300 units
        assert_eq!(result.compute_cost(10), 3000); // 300 * 10 = 3000 micro-SEAL
    }

    #[test]
    fn test_compute_cost_overflow_safe() {
        let result = InferenceResult {
            request_id: "req_1".into(),
            output: "test".into(),
            input_tokens: u32::MAX,
            output_tokens: u32::MAX,
            node_id: "node_1".into(),
            attestation_hash: vec![],
        };

        // Should not panic (saturating_mul)
        let cost = result.compute_cost(u64::MAX);
        assert_eq!(cost, u64::MAX); // Saturates
    }
}
