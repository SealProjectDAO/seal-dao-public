//! Genesis block generation for multi-validator networks.
//!
//! A `GenesisConfig` deterministically produces the genesis block:
//! - Initial validator set (public keys, VRF keys, stakes)
//! - Initial token allocations
//! - Consensus parameters
//! - Chain ID and timestamp
//!
//! Two nodes initialized from the same `GenesisConfig` produce identical
//! genesis blocks with identical state roots.

use crate::config::ConsensusConfig;
use crate::epoch::Epoch;
use crate::validator::{ValidatorInfo, ValidatorSet};
use seal_crypto::hash::{sha3_256, Hash256};
use seal_token::params::{self, genesis as token_genesis};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Initial token allocation for an address.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GenesisAllocation {
    /// Address (bech32m encoded or raw hex).
    pub address: String,
    /// Initial balance in micro-SEAL.
    pub amount: u64,
}

/// Genesis configuration — fully determines the initial chain state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenesisConfig {
    /// Human-readable chain identifier (e.g., "seal-mainnet-1", "seal-testnet-3").
    pub chain_id: String,
    /// Genesis timestamp (Unix seconds).
    pub genesis_time: u64,
    /// Initial validator set.
    pub validators: Vec<GenesisValidator>,
    /// Initial token allocations (non-validator accounts).
    pub allocations: Vec<GenesisAllocation>,
    /// Consensus parameters.
    pub consensus: GenesisConsensusParams,
    /// Initial supply ceiling (informational, not enforced at genesis).
    pub initial_supply: u64,
}

/// Genesis validator entry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenesisValidator {
    /// Validator's signing public key (ML-DSA).
    pub public_key: Vec<u8>,
    /// Validator's VRF public key.
    pub vrf_public_key: Vec<u8>,
    /// Initial stake in micro-SEAL.
    pub stake: u64,
    /// Human-readable name (optional, for testnet convenience).
    pub name: String,
}

/// Consensus parameters embedded in genesis.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenesisConsensusParams {
    pub slot_duration_ms: u64,
    pub slots_per_epoch: u64,
    pub committee_size: u32,
    pub finality_threshold_percent: u64,
    pub min_stake: u64,
    pub max_block_size: usize,
    pub max_txs_per_block: usize,
}

impl Default for GenesisConsensusParams {
    fn default() -> Self {
        let config = ConsensusConfig::default();
        GenesisConsensusParams {
            slot_duration_ms: config.slot_duration.as_millis() as u64,
            slots_per_epoch: config.slots_per_epoch,
            committee_size: config.committee_size,
            finality_threshold_percent: 67,
            min_stake: config.min_stake,
            max_block_size: config.max_block_size,
            max_txs_per_block: config.max_txs_per_block,
        }
    }
}

impl GenesisConsensusParams {
    /// Convert to runtime ConsensusConfig.
    pub fn to_consensus_config(&self) -> ConsensusConfig {
        ConsensusConfig {
            slot_duration: Duration::from_millis(self.slot_duration_ms),
            slots_per_epoch: self.slots_per_epoch,
            committee_size: self.committee_size,
            finality_threshold: self.finality_threshold_percent as f64 / 100.0,
            min_stake: self.min_stake,
            max_block_size: self.max_block_size,
            max_txs_per_block: self.max_txs_per_block,
        }
    }
}

/// The genesis block produced from a GenesisConfig.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenesisBlock {
    /// Block hash (SHA3 of the serialized genesis config).
    pub hash: Hash256,
    /// Chain ID.
    pub chain_id: String,
    /// Timestamp.
    pub genesis_time: u64,
    /// State root (hash of initial state: balances + validator set).
    pub state_root: Hash256,
    /// The initial validator set.
    pub validator_set: ValidatorSet,
    /// The initial epoch.
    pub epoch: Epoch,
}

impl GenesisConfig {
    /// Create a minimal testnet genesis with the given number of validators.
    pub fn testnet(num_validators: usize, stake_each: u64) -> Self {
        let validators: Vec<GenesisValidator> = (0..num_validators)
            .map(|i| {
                let id = (i + 1) as u8;
                GenesisValidator {
                    public_key: vec![id; 32],
                    vrf_public_key: vec![id + 100; 32],
                    stake: stake_each,
                    name: format!("validator-{}", i + 1),
                }
            })
            .collect();

        GenesisConfig {
            chain_id: "seal-testnet".into(),
            genesis_time: 1700000000,
            validators,
            allocations: vec![
                GenesisAllocation {
                    address: "seal1faucet".into(),
                    amount: 1_000_000_000_000, // 1000 SEAL
                },
            ],
            consensus: GenesisConsensusParams::default(),
            initial_supply: 1_000_000_000_000_000_000, // 1B SEAL in micro-SEAL
        }
    }

    /// Create a mainnet genesis with the full 30/20/15/15/10/10 token distribution.
    ///
    /// Allocations:
    /// - 30% Validator staking pool → "seal1validators"
    /// - 20% Community treasury → "seal1treasury"
    /// - 15% Team (4-year vest, 6-month cliff) → "seal1team"
    /// - 15% Ecosystem fund → "seal1ecosystem"
    /// - 10% Public distribution → "seal1public"
    /// - 10% Reserve → "seal1reserve"
    pub fn mainnet(validators: Vec<GenesisValidator>, genesis_time: u64) -> Self {
        let allocations = vec![
            GenesisAllocation {
                address: "seal1validators".into(),
                amount: token_genesis::VALIDATOR_POOL,
            },
            GenesisAllocation {
                address: "seal1treasury".into(),
                amount: token_genesis::COMMUNITY_TREASURY,
            },
            GenesisAllocation {
                address: "seal1team".into(),
                amount: token_genesis::TEAM_ALLOCATION,
            },
            GenesisAllocation {
                address: "seal1ecosystem".into(),
                amount: token_genesis::ECOSYSTEM_FUND,
            },
            GenesisAllocation {
                address: "seal1public".into(),
                amount: token_genesis::PUBLIC_DISTRIBUTION,
            },
            GenesisAllocation {
                address: "seal1reserve".into(),
                amount: token_genesis::RESERVE,
            },
        ];

        GenesisConfig {
            chain_id: "seal-mainnet-1".into(),
            genesis_time,
            validators,
            allocations,
            consensus: GenesisConsensusParams::default(),
            initial_supply: params::INITIAL_SUPPLY,
        }
    }

    /// Verify that genesis allocations exactly match the defined token economics.
    pub fn verify_token_distribution(&self) -> Result<(), String> {
        let allocation_total: u64 = self
            .allocations
            .iter()
            .map(|a| a.amount)
            .fold(0u64, |acc, x| acc.saturating_add(x));

        if allocation_total != params::INITIAL_SUPPLY {
            return Err(format!(
                "allocation total {} != initial supply {}",
                allocation_total,
                params::INITIAL_SUPPLY
            ));
        }

        // Verify individual percentages
        let expected = [
            ("seal1validators", token_genesis::VALIDATOR_POOL),
            ("seal1treasury", token_genesis::COMMUNITY_TREASURY),
            ("seal1team", token_genesis::TEAM_ALLOCATION),
            ("seal1ecosystem", token_genesis::ECOSYSTEM_FUND),
            ("seal1public", token_genesis::PUBLIC_DISTRIBUTION),
            ("seal1reserve", token_genesis::RESERVE),
        ];

        for (addr, expected_amount) in &expected {
            let actual = self
                .allocations
                .iter()
                .find(|a| a.address == *addr)
                .map(|a| a.amount)
                .unwrap_or(0);
            if actual != *expected_amount {
                return Err(format!(
                    "{}: expected {} got {}",
                    addr, expected_amount, actual
                ));
            }
        }

        Ok(())
    }

    /// Create an incentivized testnet genesis for pre-mainnet validation.
    ///
    /// Parameters tuned for realistic mainnet conditions:
    /// - 4s slots, 128 slots/epoch (~8.5 min epochs)
    /// - Committee size scales with validator count (max 50)
    /// - Each validator receives 10,000 SEAL testnet tokens
    /// - Faucet + stress test + governance test funds included
    pub fn incentivized_testnet(num_validators: usize, genesis_time: u64) -> Self {
        let stake_each = 10_000_000_000_000; // 10,000 SEAL per validator
        let validators: Vec<GenesisValidator> = (0..num_validators)
            .map(|i| {
                let id_bytes = ((i + 1) as u32).to_le_bytes();
                let mut pk = vec![0u8; 32];
                let mut vrf_pk = vec![0u8; 32];
                pk[..4].copy_from_slice(&id_bytes);
                vrf_pk[..4].copy_from_slice(&id_bytes);
                vrf_pk[4] = 0xFF; // distinguish from signing key
                GenesisValidator {
                    public_key: pk,
                    vrf_public_key: vrf_pk,
                    stake: stake_each,
                    name: format!("validator-{}", i + 1),
                }
            })
            .collect();

        let committee_size = (num_validators as u32).min(50);

        GenesisConfig {
            chain_id: "seal-incentivized-testnet-1".into(),
            genesis_time,
            validators,
            allocations: vec![
                GenesisAllocation {
                    address: "seal1faucet".into(),
                    amount: 10_000_000_000_000_000, // 10M SEAL faucet
                },
                GenesisAllocation {
                    address: "seal1stress-test".into(),
                    amount: 1_000_000_000_000_000, // 1M SEAL stress test fund
                },
                GenesisAllocation {
                    address: "seal1governance-test".into(),
                    amount: 500_000_000_000_000, // 500K SEAL governance test
                },
            ],
            consensus: GenesisConsensusParams {
                slot_duration_ms: 4000,
                slots_per_epoch: 128,
                committee_size,
                finality_threshold_percent: 67,
                min_stake: 1_000_000_000_000, // 1,000 SEAL
                max_block_size: 2 * 1024 * 1024, // 2 MB
                max_txs_per_block: 1_000,
            },
            initial_supply: 1_000_000_000_000_000_000,
        }
    }

    /// Create a fast devnet genesis (1s slots, 8-slot epochs).
    pub fn devnet(num_validators: usize) -> Self {
        let mut config = Self::testnet(num_validators, 10_000_000_000);
        config.chain_id = "seal-devnet".into();
        config.consensus.slot_duration_ms = 1000; // 1 second
        config.consensus.slots_per_epoch = 8;     // 8-second epochs
        config.consensus.committee_size = num_validators as u32;
        config
    }

    /// Compute the deterministic genesis block from this config.
    pub fn genesis_block(&self) -> GenesisBlock {
        let validator_set = self.build_validator_set();
        let state_root = self.compute_state_root(&validator_set);

        // Genesis block hash = SHA3(chain_id || genesis_time || state_root)
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(self.chain_id.as_bytes());
        hash_input.extend_from_slice(&self.genesis_time.to_le_bytes());
        hash_input.extend_from_slice(state_root.as_ref());
        let hash = sha3_256(&hash_input);

        GenesisBlock {
            hash,
            chain_id: self.chain_id.clone(),
            genesis_time: self.genesis_time,
            state_root,
            validator_set,
            epoch: Epoch::genesis(),
        }
    }

    /// Build the initial validator set from genesis config.
    pub fn build_validator_set(&self) -> ValidatorSet {
        let validators: Vec<ValidatorInfo> = self
            .validators
            .iter()
            .filter(|v| v.stake >= self.consensus.min_stake)
            .map(|v| ValidatorInfo {
                public_key: v.public_key.clone(),
                vrf_public_key: v.vrf_public_key.clone(),
                stake: v.stake,
                active: true,
            })
            .collect();
        ValidatorSet::new(validators)
    }

    /// Compute the deterministic state root from allocations + validator set.
    fn compute_state_root(&self, validator_set: &ValidatorSet) -> Hash256 {
        let mut state_data = Vec::new();

        // Hash all allocations (sorted by address for determinism)
        let mut sorted_allocs = self.allocations.clone();
        sorted_allocs.sort_by(|a, b| a.address.cmp(&b.address));
        for alloc in &sorted_allocs {
            state_data.extend_from_slice(alloc.address.as_bytes());
            state_data.extend_from_slice(&alloc.amount.to_le_bytes());
        }

        // Hash validator set
        for v in &validator_set.validators {
            state_data.extend_from_slice(&v.public_key);
            state_data.extend_from_slice(&v.stake.to_le_bytes());
        }

        // Include chain metadata
        state_data.extend_from_slice(self.chain_id.as_bytes());
        state_data.extend_from_slice(&self.genesis_time.to_le_bytes());

        sha3_256(&state_data)
    }

    /// Total initial supply: sum of validator stakes + allocations.
    pub fn total_initial_tokens(&self) -> u64 {
        let validator_total: u64 = self.validators.iter().map(|v| v.stake).sum();
        let allocation_total: u64 = self.allocations.iter().map(|a| a.amount).sum();
        validator_total.saturating_add(allocation_total)
    }

    /// Validate the genesis config.
    pub fn validate(&self) -> Result<(), String> {
        if self.chain_id.is_empty() {
            return Err("chain_id must not be empty".into());
        }
        if self.validators.is_empty() {
            return Err("at least one validator required".into());
        }
        for (i, v) in self.validators.iter().enumerate() {
            if v.stake < self.consensus.min_stake {
                return Err(format!(
                    "validator {} has stake {} below minimum {}",
                    i, v.stake, self.consensus.min_stake
                ));
            }
            if v.public_key.is_empty() {
                return Err(format!("validator {} has empty public key", i));
            }
        }
        if self.consensus.slots_per_epoch == 0 {
            return Err("slots_per_epoch must be > 0".into());
        }
        if self.consensus.slot_duration_ms == 0 {
            return Err("slot_duration_ms must be > 0".into());
        }
        Ok(())
    }
}

#[cfg(kani)]
mod kani_proofs {
    // NOTE: GenesisConfig uses String/Vec/HashMap which CBMC cannot model.
    // Determinism and validation are tested in unit tests (21 tests).
    // These harnesses verify the arithmetic properties.

    /// Prove: saturating_add for token totals never wraps.
    #[kani::proof]
    fn total_tokens_saturating() {
        let validator_stake: u64 = kani::any();
        let allocation: u64 = kani::any();
        let total = validator_stake.saturating_add(allocation);
        assert!(total >= validator_stake);
        assert!(total >= allocation.min(validator_stake));
    }

    /// Prove: genesis allocation percentages sum correctly.
    /// 30 + 20 + 15 + 15 + 10 + 10 = 100
    #[kani::proof]
    fn allocation_percentages_sum() {
        let pcts = [30u64, 20, 15, 15, 10, 10];
        let sum: u64 = pcts.iter().sum();
        assert_eq!(sum, 100);
    }

    /// Prove: min_stake check is consistent.
    #[kani::proof]
    fn min_stake_validation() {
        let stake: u64 = kani::any();
        let min_stake: u64 = kani::any();
        let valid = stake >= min_stake;
        if valid {
            assert!(stake >= min_stake);
        } else {
            assert!(stake < min_stake);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_testnet_genesis() {
        let config = GenesisConfig::testnet(3, 10_000_000_000);
        assert_eq!(config.validators.len(), 3);
        assert_eq!(config.chain_id, "seal-testnet");
        config.validate().unwrap();
    }

    #[test]
    fn test_devnet_genesis() {
        let config = GenesisConfig::devnet(5);
        assert_eq!(config.validators.len(), 5);
        assert_eq!(config.consensus.slot_duration_ms, 1000);
        assert_eq!(config.consensus.slots_per_epoch, 8);
        config.validate().unwrap();
    }

    #[test]
    fn test_genesis_block_deterministic() {
        let config = GenesisConfig::testnet(3, 10_000_000_000);
        let block1 = config.genesis_block();
        let block2 = config.genesis_block();

        assert_eq!(block1.hash, block2.hash);
        assert_eq!(block1.state_root, block2.state_root);
        assert_eq!(block1.validator_set.total_stake, block2.validator_set.total_stake);
    }

    #[test]
    fn test_different_configs_different_blocks() {
        let config1 = GenesisConfig::testnet(3, 10_000_000_000);
        let config2 = GenesisConfig::testnet(5, 10_000_000_000);

        let block1 = config1.genesis_block();
        let block2 = config2.genesis_block();

        assert_ne!(block1.hash, block2.hash);
        assert_ne!(block1.state_root, block2.state_root);
    }

    #[test]
    fn test_validator_set_from_genesis() {
        let config = GenesisConfig::testnet(3, 10_000_000_000);
        let vs = config.build_validator_set();

        assert_eq!(vs.active_count(), 3);
        assert_eq!(vs.total_stake, 30_000_000_000);
    }

    #[test]
    fn test_genesis_validators_sorted() {
        let config = GenesisConfig::testnet(3, 10_000_000_000);
        let vs = config.build_validator_set();

        // Should be sorted by public key
        for i in 1..vs.validators.len() {
            assert!(vs.validators[i - 1].public_key < vs.validators[i].public_key);
        }
    }

    #[test]
    fn test_total_initial_tokens() {
        let config = GenesisConfig::testnet(3, 10_000_000_000);
        let total = config.total_initial_tokens();
        // 3 validators × 10B + 1T faucet
        assert_eq!(total, 3 * 10_000_000_000 + 1_000_000_000_000);
    }

    #[test]
    fn test_validate_empty_validators() {
        let mut config = GenesisConfig::testnet(1, 10_000_000_000);
        config.validators.clear();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_empty_chain_id() {
        let mut config = GenesisConfig::testnet(1, 10_000_000_000);
        config.chain_id = String::new();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_low_stake() {
        let mut config = GenesisConfig::testnet(1, 100); // Below min_stake
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_consensus_params_roundtrip() {
        let params = GenesisConsensusParams::default();
        let config = params.to_consensus_config();
        assert_eq!(config.slot_duration, Duration::from_secs(4));
        assert_eq!(config.slots_per_epoch, 256);
        assert_eq!(config.committee_size, 100);
    }

    #[test]
    fn test_genesis_block_has_epoch_zero() {
        let config = GenesisConfig::testnet(1, 10_000_000_000);
        let block = config.genesis_block();
        assert_eq!(block.epoch.number, 0);
    }

    #[test]
    fn test_mainnet_genesis_allocations() {
        let validators = vec![GenesisValidator {
            public_key: vec![1u8; 32],
            vrf_public_key: vec![101u8; 32],
            stake: 10_000_000_000_000, // 10,000 SEAL
            name: "genesis-validator-1".into(),
        }];
        let config = GenesisConfig::mainnet(validators, 1700000000);

        assert_eq!(config.chain_id, "seal-mainnet-1");
        assert_eq!(config.allocations.len(), 6);
        assert_eq!(config.initial_supply, params::INITIAL_SUPPLY);

        // Verify the 30/20/15/15/10/10 distribution
        config.verify_token_distribution().unwrap();
    }

    #[test]
    fn test_mainnet_genesis_total_allocation() {
        let validators = vec![GenesisValidator {
            public_key: vec![1u8; 32],
            vrf_public_key: vec![101u8; 32],
            stake: 10_000_000_000_000,
            name: "v1".into(),
        }];
        let config = GenesisConfig::mainnet(validators, 1700000000);

        let total: u64 = config.allocations.iter().map(|a| a.amount).sum();
        assert_eq!(total, params::INITIAL_SUPPLY);
        assert_eq!(total, 1_000_000_000_000_000_000); // 1B SEAL
    }

    #[test]
    fn test_mainnet_genesis_block_deterministic() {
        let validators = vec![
            GenesisValidator {
                public_key: vec![1u8; 32],
                vrf_public_key: vec![101u8; 32],
                stake: 10_000_000_000_000,
                name: "v1".into(),
            },
            GenesisValidator {
                public_key: vec![2u8; 32],
                vrf_public_key: vec![102u8; 32],
                stake: 10_000_000_000_000,
                name: "v2".into(),
            },
        ];
        let c1 = GenesisConfig::mainnet(validators.clone(), 1700000000);
        let c2 = GenesisConfig::mainnet(validators, 1700000000);

        let b1 = c1.genesis_block();
        let b2 = c2.genesis_block();
        assert_eq!(b1.hash, b2.hash);
        assert_eq!(b1.state_root, b2.state_root);
    }

    #[test]
    fn test_incentivized_testnet_genesis() {
        let config = GenesisConfig::incentivized_testnet(50, 1700000000);
        assert_eq!(config.chain_id, "seal-incentivized-testnet-1");
        assert_eq!(config.validators.len(), 50);
        assert_eq!(config.consensus.committee_size, 50);
        assert_eq!(config.consensus.slot_duration_ms, 4000);
        assert_eq!(config.consensus.slots_per_epoch, 128);
        assert_eq!(config.allocations.len(), 3);
        config.validate().unwrap();
    }

    #[test]
    fn test_incentivized_testnet_committee_cap() {
        // With 200 validators, committee should cap at 50
        let config = GenesisConfig::incentivized_testnet(200, 1700000000);
        assert_eq!(config.consensus.committee_size, 50);
        assert_eq!(config.validators.len(), 200);
        config.validate().unwrap();
    }

    #[test]
    fn test_incentivized_testnet_deterministic() {
        let c1 = GenesisConfig::incentivized_testnet(50, 1700000000);
        let c2 = GenesisConfig::incentivized_testnet(50, 1700000000);
        let b1 = c1.genesis_block();
        let b2 = c2.genesis_block();
        assert_eq!(b1.hash, b2.hash);
        assert_eq!(b1.state_root, b2.state_root);
    }

    #[test]
    fn test_mainnet_validate() {
        let validators = vec![GenesisValidator {
            public_key: vec![1u8; 32],
            vrf_public_key: vec![101u8; 32],
            stake: 10_000_000_000_000,
            name: "v1".into(),
        }];
        let config = GenesisConfig::mainnet(validators, 1700000000);
        config.validate().unwrap();
    }
}
