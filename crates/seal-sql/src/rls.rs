//! PostgreSQL-compatible Row-Level Security (RLS).
//!
//! Implements:
//! - `ALTER TABLE <table>` ENABLE ROW LEVEL SECURITY
//! - `CREATE POLICY <name> ON <table> FOR <action> USING (<predicate>)`
//!
//! Policies filter rows based on the current user (CURRENT_USER()).
//! When RLS is enabled on a table, all queries are filtered through
//! applicable policies. Without a matching policy, access is denied.

use crate::error::SqlError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// SQL operation types that policies apply to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyAction {
    Select,
    Insert,
    Update,
    Delete,
    All,
}

impl PolicyAction {
    /// Check if this action covers a given operation.
    pub fn covers(&self, action: &PolicyAction) -> bool {
        matches!(self, PolicyAction::All) || self == action
    }
}

/// A row-level security policy.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Policy {
    /// Policy name.
    pub name: String,
    /// Table this policy applies to.
    pub table_name: String,
    /// Which operations this policy governs.
    pub action: PolicyAction,
    /// The USING predicate as a string expression.
    /// Evaluated per-row with CURRENT_USER() bound to the caller.
    pub using_expr: String,
    /// Optional WITH CHECK predicate (for INSERT/UPDATE).
    pub with_check_expr: Option<String>,
}

/// Token balance checker — injected to evaluate HAS_TOKEN() predicates.
/// Returns the user's balance for a given token symbol.
pub type TokenBalanceChecker = Box<dyn Fn(&str, &str) -> u64 + Send + Sync>;

/// Manages RLS policies for tables.
#[derive(Default)]
pub struct RlsManager {
    /// Tables with RLS enabled.
    rls_enabled: HashMap<String, bool>,
    /// Policies keyed by table name.
    policies: HashMap<String, Vec<Policy>>,
    /// Optional token balance checker for HAS_TOKEN() predicates.
    token_checker: Option<TokenBalanceChecker>,
}

impl Clone for RlsManager {
    fn clone(&self) -> Self {
        RlsManager {
            rls_enabled: self.rls_enabled.clone(),
            policies: self.policies.clone(),
            token_checker: None, // Can't clone function pointers
        }
    }
}

impl std::fmt::Debug for RlsManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RlsManager")
            .field("rls_enabled", &self.rls_enabled)
            .field("policies", &self.policies)
            .field("has_token_checker", &self.token_checker.is_some())
            .finish()
    }
}

impl RlsManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a token balance checker for HAS_TOKEN() predicates.
    pub fn set_token_checker(&mut self, checker: TokenBalanceChecker) {
        self.token_checker = Some(checker);
    }

    /// Enable RLS on a table.
    pub fn enable_rls(&mut self, table_name: &str) {
        self.rls_enabled.insert(table_name.to_string(), true);
    }

    /// Disable RLS on a table.
    pub fn disable_rls(&mut self, table_name: &str) {
        self.rls_enabled.insert(table_name.to_string(), false);
    }

    /// Check if RLS is enabled on a table.
    pub fn is_rls_enabled(&self, table_name: &str) -> bool {
        self.rls_enabled.get(table_name).copied().unwrap_or(false)
    }

    /// Add a policy.
    pub fn add_policy(&mut self, policy: Policy) -> Result<(), SqlError> {
        let table = policy.table_name.clone();
        let name = policy.name.clone();

        let policies = self.policies.entry(table).or_default();
        if policies.iter().any(|p| p.name == name) {
            return Err(SqlError::Execution(format!(
                "policy '{}' already exists",
                name
            )));
        }
        policies.push(policy);
        Ok(())
    }

    /// Drop a policy by name.
    pub fn drop_policy(&mut self, table_name: &str, policy_name: &str) -> Result<(), SqlError> {
        let policies = self
            .policies
            .get_mut(table_name)
            .ok_or_else(|| SqlError::Execution(format!("no policies on table '{}'", table_name)))?;
        let before = policies.len();
        policies.retain(|p| p.name != policy_name);
        if policies.len() == before {
            return Err(SqlError::Execution(format!(
                "policy '{}' not found",
                policy_name
            )));
        }
        Ok(())
    }

    /// Get all policies for a table and action.
    pub fn get_policies(&self, table_name: &str, action: &PolicyAction) -> Vec<&Policy> {
        self.policies
            .get(table_name)
            .map(|policies| {
                policies
                    .iter()
                    .filter(|p| p.action.covers(action))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Check if an operation is allowed on a row by evaluating policies.
    ///
    /// Returns true if:
    /// - RLS is not enabled on the table, OR
    /// - At least one policy for this action evaluates to true for the row
    ///
    /// The `current_user` is the address of the transaction sender.
    /// The `owner_column` value is compared against `current_user` in simple
    /// predicate evaluation.
    pub fn check_access(
        &self,
        table_name: &str,
        action: &PolicyAction,
        current_user: &str,
        row_owner: Option<&str>,
    ) -> bool {
        if !self.is_rls_enabled(table_name) {
            return true; // RLS not enabled → allow all
        }

        let policies = self.get_policies(table_name, action);
        if policies.is_empty() {
            return false; // RLS enabled but no policy → deny all
        }

        // Evaluate policies: OR semantics (any matching policy grants access)
        for policy in &policies {
            if self.evaluate_policy(policy, current_user, row_owner) {
                return true;
            }
        }

        false
    }

    /// Simple policy predicate evaluation.
    /// Supports: "true", "owner = CURRENT_USER()", basic comparisons.
    fn evaluate_policy(
        &self,
        policy: &Policy,
        current_user: &str,
        row_owner: Option<&str>,
    ) -> bool {
        let expr = policy.using_expr.trim().to_lowercase();

        // Literal true — public access
        if expr == "true" {
            return true;
        }

        // Literal false — deny
        if expr == "false" {
            return false;
        }

        // owner = CURRENT_USER() pattern
        if expr.contains("current_user()") && expr.contains("=") {
            if let Some(owner) = row_owner {
                return owner == current_user;
            }
            return false;
        }

        // HAS_TOKEN('SYMBOL', amount) — token-gated access
        if expr.starts_with("has_token(") || expr.starts_with("has_token (") {
            return self.evaluate_has_token(&expr, current_user);
        }

        // Default: deny (fail-safe)
        false
    }

    /// Evaluate HAS_TOKEN('SYMBOL', min_amount) predicate.
    /// Returns true if current_user holds >= min_amount of the token.
    fn evaluate_has_token(&self, expr: &str, current_user: &str) -> bool {
        // Parse: has_token('GOLD', 100) or has_token('GOLD')
        let inner = expr
            .trim_start_matches("has_token")
            .trim()
            .trim_start_matches('(')
            .trim_end_matches(')')
            .trim();

        let parts: Vec<&str> = inner.split(',').map(|s| s.trim()).collect();
        if parts.is_empty() {
            return false;
        }

        let symbol = parts[0].trim_matches('\'').trim_matches('"');
        let min_amount: u64 = parts
            .get(1)
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(1); // default: must hold at least 1

        if let Some(checker) = &self.token_checker {
            let balance = checker(symbol, current_user);
            balance >= min_amount
        } else {
            false // no token checker configured → deny
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rls_disabled_allows_all() {
        let mgr = RlsManager::new();
        assert!(mgr.check_access("users", &PolicyAction::Select, "alice", None));
    }

    #[test]
    fn test_rls_enabled_no_policy_denies() {
        let mut mgr = RlsManager::new();
        mgr.enable_rls("users");
        assert!(!mgr.check_access("users", &PolicyAction::Select, "alice", None));
    }

    #[test]
    fn test_public_read_policy() {
        let mut mgr = RlsManager::new();
        mgr.enable_rls("posts");
        mgr.add_policy(Policy {
            name: "public_read".into(),
            table_name: "posts".into(),
            action: PolicyAction::Select,
            using_expr: "true".into(),
            with_check_expr: None,
        })
        .unwrap();

        assert!(mgr.check_access("posts", &PolicyAction::Select, "anyone", None));
        // Write should still be denied (no write policy)
        assert!(!mgr.check_access("posts", &PolicyAction::Insert, "anyone", None));
    }

    #[test]
    fn test_owner_write_policy() {
        let mut mgr = RlsManager::new();
        mgr.enable_rls("posts");

        // Public read
        mgr.add_policy(Policy {
            name: "public_read".into(),
            table_name: "posts".into(),
            action: PolicyAction::Select,
            using_expr: "true".into(),
            with_check_expr: None,
        })
        .unwrap();

        // Owner-only write
        mgr.add_policy(Policy {
            name: "owner_write".into(),
            table_name: "posts".into(),
            action: PolicyAction::Update,
            using_expr: "owner = CURRENT_USER()".into(),
            with_check_expr: None,
        })
        .unwrap();

        // Alice owns the row
        assert!(mgr.check_access("posts", &PolicyAction::Update, "alice", Some("alice")));
        // Bob doesn't own it
        assert!(!mgr.check_access("posts", &PolicyAction::Update, "bob", Some("alice")));
    }

    #[test]
    fn test_all_action_policy() {
        let mut mgr = RlsManager::new();
        mgr.enable_rls("data");
        mgr.add_policy(Policy {
            name: "owner_all".into(),
            table_name: "data".into(),
            action: PolicyAction::All,
            using_expr: "owner = CURRENT_USER()".into(),
            with_check_expr: None,
        })
        .unwrap();

        assert!(mgr.check_access("data", &PolicyAction::Select, "alice", Some("alice")));
        assert!(mgr.check_access("data", &PolicyAction::Update, "alice", Some("alice")));
        assert!(mgr.check_access("data", &PolicyAction::Delete, "alice", Some("alice")));
        assert!(!mgr.check_access("data", &PolicyAction::Select, "bob", Some("alice")));
    }

    #[test]
    fn test_duplicate_policy_name_rejected() {
        let mut mgr = RlsManager::new();
        mgr.add_policy(Policy {
            name: "p1".into(),
            table_name: "t".into(),
            action: PolicyAction::Select,
            using_expr: "true".into(),
            with_check_expr: None,
        })
        .unwrap();

        assert!(mgr
            .add_policy(Policy {
                name: "p1".into(),
                table_name: "t".into(),
                action: PolicyAction::Insert,
                using_expr: "true".into(),
                with_check_expr: None,
            })
            .is_err());
    }

    #[test]
    fn test_drop_policy() {
        let mut mgr = RlsManager::new();
        mgr.enable_rls("t");
        mgr.add_policy(Policy {
            name: "p1".into(),
            table_name: "t".into(),
            action: PolicyAction::Select,
            using_expr: "true".into(),
            with_check_expr: None,
        })
        .unwrap();

        assert!(mgr.check_access("t", &PolicyAction::Select, "any", None));
        mgr.drop_policy("t", "p1").unwrap();
        assert!(!mgr.check_access("t", &PolicyAction::Select, "any", None));
    }

    #[test]
    fn test_disable_rls() {
        let mut mgr = RlsManager::new();
        mgr.enable_rls("t");
        assert!(!mgr.check_access("t", &PolicyAction::Select, "any", None)); // Denied

        mgr.disable_rls("t");
        assert!(mgr.check_access("t", &PolicyAction::Select, "any", None)); // Allowed
    }

    #[test]
    fn test_multiple_policies_or_semantics() {
        let mut mgr = RlsManager::new();
        mgr.enable_rls("t");

        // Policy 1: owner can access
        mgr.add_policy(Policy {
            name: "owner".into(),
            table_name: "t".into(),
            action: PolicyAction::Select,
            using_expr: "owner = CURRENT_USER()".into(),
            with_check_expr: None,
        })
        .unwrap();

        // Policy 2: public access (overrides owner check via OR)
        mgr.add_policy(Policy {
            name: "public".into(),
            table_name: "t".into(),
            action: PolicyAction::Select,
            using_expr: "true".into(),
            with_check_expr: None,
        })
        .unwrap();

        // Anyone can access (public policy matches)
        assert!(mgr.check_access("t", &PolicyAction::Select, "stranger", Some("alice")));
    }
}
