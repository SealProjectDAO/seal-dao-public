//! Treasury allocation and disbursement.
//!
//! A fixed percentage of each epoch's emission is directed to the protocol
//! treasury. Funds can only be disbursed via governance approval.

use crate::error::TokenError;

/// Default treasury allocation: 10% of emission.
pub const DEFAULT_TREASURY_PERCENT: u64 = 10;

/// Treasury tracks allocation and disbursement of protocol funds.
#[derive(Debug, Clone)]
pub struct Treasury {
    /// Address that holds treasury funds on-chain.
    pub address: String,
    /// Percentage of emission allocated to treasury (0–100).
    pub allocation_percent: u64,
    /// Total allocated to treasury (cumulative, micro-SEAL).
    pub total_allocated: u64,
    /// Total disbursed from treasury (cumulative, micro-SEAL).
    pub total_disbursed: u64,
    /// Whether disbursement is currently approved by governance.
    pub governance_approved: bool,
}

impl Treasury {
    /// Create a new treasury with the given address and default allocation.
    pub fn new(address: &str) -> Self {
        Treasury {
            address: address.to_string(),
            allocation_percent: DEFAULT_TREASURY_PERCENT,
            total_allocated: 0,
            total_disbursed: 0,
            governance_approved: false,
        }
    }

    /// Create a treasury with a custom allocation percentage.
    pub fn with_allocation(address: &str, percent: u64) -> Self {
        Treasury {
            address: address.to_string(),
            allocation_percent: percent.min(100),
            total_allocated: 0,
            total_disbursed: 0,
            governance_approved: false,
        }
    }

    /// Split a total emission into (treasury_share, validator_share).
    ///
    /// treasury_share = total_emission * allocation_percent / 100
    /// validator_share = total_emission - treasury_share
    ///
    /// Uses checked arithmetic. Updates total_allocated.
    pub fn allocate_from_emission(
        &mut self,
        total_emission: u64,
    ) -> Result<(u64, u64), TokenError> {
        let treasury_share = total_emission
            .checked_mul(self.allocation_percent)
            .ok_or(TokenError::Overflow)?
            / 100;
        let validator_share = total_emission.saturating_sub(treasury_share);

        self.total_allocated = self
            .total_allocated
            .checked_add(treasury_share)
            .ok_or(TokenError::Overflow)?;

        Ok((treasury_share, validator_share))
    }

    /// Disburse funds from the treasury. Requires governance approval.
    ///
    /// Returns the amount disbursed on success.
    pub fn disburse(&mut self, amount: u64) -> Result<u64, TokenError> {
        if !self.governance_approved {
            return Err(TokenError::GovernanceRequired);
        }

        let available = self.total_allocated.saturating_sub(self.total_disbursed);
        if amount > available {
            return Err(TokenError::InsufficientTreasury {
                need: amount,
                have: available,
            });
        }

        self.total_disbursed = self
            .total_disbursed
            .checked_add(amount)
            .ok_or(TokenError::Overflow)?;

        Ok(amount)
    }

    /// Available treasury balance (allocated - disbursed).
    pub fn available_balance(&self) -> u64 {
        self.total_allocated.saturating_sub(self.total_disbursed)
    }

    /// Approve disbursement via governance vote.
    pub fn approve_disbursement(&mut self) {
        self.governance_approved = true;
    }

    /// Revoke disbursement approval.
    pub fn revoke_disbursement(&mut self) {
        self.governance_approved = false;
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// Prove that for any total_emission and any allocation_percent (0..=100),
    /// when allocation succeeds the shares satisfy:
    ///   treasury_share + validator_share <= total_emission
    /// and the rounding loss is at most (allocation_percent - 1) due to
    /// integer division truncation (i.e., less than allocation_percent).
    #[kani::proof]
    fn allocation_conserves_total() {
        let total_emission: u64 = kani::any();
        let percent: u64 = kani::any();
        kani::assume(percent <= 100);

        let mut treasury = Treasury::with_allocation("kani", percent);

        if let Ok((treasury_share, validator_share)) = treasury.allocate_from_emission(total_emission) {
            // The two shares must never exceed the original emission.
            let sum = treasury_share + validator_share;
            assert!(sum <= total_emission, "shares exceed total_emission");

            // The rounding loss from integer division is at most
            // (allocation_percent - 1), which is strictly less than
            // allocation_percent. (When percent == 0, loss is 0.)
            let loss = total_emission - sum;
            assert!(
                loss < percent.max(1),
                "rounding loss exceeds bound"
            );
        }
        // If allocation returns Err (overflow), that is acceptable — the
        // harness only constrains the Ok path.
    }

    /// Prove that after one allocation followed by one disbursement,
    /// total_disbursed never exceeds total_allocated.
    #[kani::proof]
    fn disburse_never_exceeds_available() {
        let total_emission: u64 = kani::any();
        let disburse_amount: u64 = kani::any();
        let percent: u64 = kani::any();
        kani::assume(percent <= 100);

        let mut treasury = Treasury::with_allocation("kani", percent);

        // Allocate — skip if it overflows.
        if treasury.allocate_from_emission(total_emission).is_ok() {
            treasury.approve_disbursement();

            // Attempt disbursement (may succeed or fail).
            let _ = treasury.disburse(disburse_amount);

            // Invariant: total_disbursed <= total_allocated always holds.
            assert!(
                treasury.total_disbursed <= treasury.total_allocated,
                "total_disbursed exceeded total_allocated"
            );
        }
    }

    /// Prove that disburse() always returns Err(GovernanceRequired) when
    /// governance_approved is false, regardless of the amount requested.
    #[kani::proof]
    fn governance_gate_enforced() {
        let total_emission: u64 = kani::any();
        let disburse_amount: u64 = kani::any();

        let mut treasury = Treasury::new("kani");

        // Allocate some funds (ignore overflow errors).
        let _ = treasury.allocate_from_emission(total_emission);

        // Governance is NOT approved (default from new()).
        assert!(!treasury.governance_approved);

        let result = treasury.disburse(disburse_amount);
        assert!(
            result == Err(TokenError::GovernanceRequired),
            "disburse must fail with GovernanceRequired when not approved"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_treasury_default() {
        let treasury = Treasury::new("treasury_addr");
        assert_eq!(treasury.address, "treasury_addr");
        assert_eq!(treasury.allocation_percent, DEFAULT_TREASURY_PERCENT);
        assert_eq!(treasury.total_allocated, 0);
        assert_eq!(treasury.total_disbursed, 0);
        assert!(!treasury.governance_approved);
    }

    #[test]
    fn test_treasury_custom_allocation() {
        let treasury = Treasury::with_allocation("t", 15);
        assert_eq!(treasury.allocation_percent, 15);
    }

    #[test]
    fn test_treasury_allocation_capped_at_100() {
        let treasury = Treasury::with_allocation("t", 150);
        assert_eq!(treasury.allocation_percent, 100);
    }

    #[test]
    fn test_allocate_from_emission() {
        let mut treasury = Treasury::new("t");
        // 10% of 1000 = 100 treasury, 900 validators
        let (t_share, v_share) = treasury.allocate_from_emission(1000).unwrap();
        assert_eq!(t_share, 100);
        assert_eq!(v_share, 900);
        assert_eq!(treasury.total_allocated, 100);
    }

    #[test]
    fn test_allocate_multiple_epochs() {
        let mut treasury = Treasury::new("t");
        treasury.allocate_from_emission(1000).unwrap();
        treasury.allocate_from_emission(2000).unwrap();
        // total_allocated = 100 + 200 = 300
        assert_eq!(treasury.total_allocated, 300);
        assert_eq!(treasury.available_balance(), 300);
    }

    #[test]
    fn test_disburse_requires_governance() {
        let mut treasury = Treasury::new("t");
        treasury.allocate_from_emission(10000).unwrap();

        // Without governance approval, disbursement fails
        let result = treasury.disburse(500);
        assert_eq!(result, Err(TokenError::GovernanceRequired));
    }

    #[test]
    fn test_disburse_with_approval() {
        let mut treasury = Treasury::new("t");
        treasury.allocate_from_emission(10000).unwrap(); // 1000 to treasury
        treasury.approve_disbursement();

        let disbursed = treasury.disburse(500).unwrap();
        assert_eq!(disbursed, 500);
        assert_eq!(treasury.total_disbursed, 500);
        assert_eq!(treasury.available_balance(), 500); // 1000 - 500
    }

    #[test]
    fn test_disburse_insufficient() {
        let mut treasury = Treasury::new("t");
        treasury.allocate_from_emission(1000).unwrap(); // 100 to treasury
        treasury.approve_disbursement();

        let result = treasury.disburse(200);
        assert_eq!(
            result,
            Err(TokenError::InsufficientTreasury {
                need: 200,
                have: 100,
            })
        );
    }

    #[test]
    fn test_revoke_disbursement() {
        let mut treasury = Treasury::new("t");
        treasury.allocate_from_emission(10000).unwrap();
        treasury.approve_disbursement();

        // Disbursement works
        assert!(treasury.disburse(500).is_ok());

        // Revoke and try again
        treasury.revoke_disbursement();
        assert_eq!(treasury.disburse(100), Err(TokenError::GovernanceRequired));
    }

    #[test]
    fn test_zero_emission_allocation() {
        let mut treasury = Treasury::new("t");
        let (t_share, v_share) = treasury.allocate_from_emission(0).unwrap();
        assert_eq!(t_share, 0);
        assert_eq!(v_share, 0);
    }

    #[test]
    fn test_zero_percent_allocation() {
        let mut treasury = Treasury::with_allocation("t", 0);
        let (t_share, v_share) = treasury.allocate_from_emission(1000).unwrap();
        assert_eq!(t_share, 0);
        assert_eq!(v_share, 1000);
    }

    #[test]
    fn test_full_allocation() {
        let mut treasury = Treasury::with_allocation("t", 100);
        let (t_share, v_share) = treasury.allocate_from_emission(1000).unwrap();
        assert_eq!(t_share, 1000);
        assert_eq!(v_share, 0);
    }

    #[test]
    fn test_available_balance_after_disbursements() {
        let mut treasury = Treasury::new("t");
        treasury.allocate_from_emission(5000).unwrap(); // 500 to treasury
        treasury.approve_disbursement();

        treasury.disburse(100).unwrap();
        assert_eq!(treasury.available_balance(), 400);

        treasury.disburse(200).unwrap();
        assert_eq!(treasury.available_balance(), 200);

        treasury.disburse(200).unwrap();
        assert_eq!(treasury.available_balance(), 0);
    }
}
