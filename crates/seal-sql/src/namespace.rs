//! App namespace management.
//!
//! Each application on Seal lives in its own namespace (e.g., "my_app.seal").
//! Tables, policies, and indexes are scoped to the namespace.
//! Cross-app access is controlled by visibility (PUBLIC/SHARED/PRIVATE).

use crate::engine::Engine;
use crate::error::SqlError;
use crate::rls::RlsManager;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Visibility level for tables (see SPEC.md §16.4).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Visibility {
    /// Only the owning app can access.
    #[default]
    Private,
    /// Explicitly granted apps can read.
    Shared { granted_apps: Vec<String> },
    /// Any app can read.
    Public,
}

/// An application namespace containing tables and policies.
pub struct AppNamespace {
    /// Namespace name (e.g., "my_app.seal").
    pub name: String,
    /// Owner address (Seal address that deployed the app).
    pub owner: String,
    /// SQL engine for this namespace.
    pub engine: Engine,
    /// RLS policy manager.
    pub rls: RlsManager,
    /// Table visibility settings.
    pub visibility: HashMap<String, Visibility>,
}

impl AppNamespace {
    /// Create a new app namespace.
    pub fn new(name: String, owner: String) -> Self {
        AppNamespace {
            name,
            owner,
            engine: Engine::new(),
            rls: RlsManager::new(),
            visibility: HashMap::new(),
        }
    }

    /// Deploy a schema (CREATE TABLE statements) into this namespace.
    pub fn deploy_schema(&mut self, sql: &str) -> Result<(), SqlError> {
        self.engine.execute(sql)?;
        Ok(())
    }

    /// Execute SQL as a given user (respects RLS if enabled).
    ///
    /// For writes (INSERT/UPDATE/DELETE): checks RLS policies before executing.
    /// For reads (SELECT): executes then filters results by RLS policies.
    /// For DDL (CREATE/ALTER/DROP): always allowed (owner only in production).
    pub fn execute_as(
        &mut self,
        sql: &str,
        user: &str,
    ) -> Result<crate::engine::QueryResult, SqlError> {
        let trimmed = sql.trim_start().to_uppercase();

        // DDL always allowed (access control is at the namespace level)
        if trimmed.starts_with("CREATE")
            || trimmed.starts_with("ALTER")
            || trimmed.starts_with("DROP")
        {
            return self.engine.execute(sql);
        }

        // For writes, check RLS before executing
        if trimmed.starts_with("INSERT")
            || trimmed.starts_with("UPDATE")
            || trimmed.starts_with("DELETE")
        {
            // Extract table name (simplified: first word after INTO/FROM/UPDATE)
            let table = extract_table_name(&trimmed);
            if let Some(table_name) = table {
                let action = if trimmed.starts_with("INSERT") {
                    crate::rls::PolicyAction::Insert
                } else if trimmed.starts_with("UPDATE") {
                    crate::rls::PolicyAction::Update
                } else {
                    crate::rls::PolicyAction::Delete
                };

                // Check if user has write access (owner check for write policies)
                if !self
                    .rls
                    .check_access(&table_name, &action, user, Some(user))
                {
                    return Err(SqlError::Execution(format!(
                        "RLS: {:?} denied on table '{}' for user '{}'",
                        action, table_name, user
                    )));
                }
            }
        }

        // Execute the SQL
        let mut result = self.engine.execute(sql)?;

        // For SELECTs with RLS enabled, filter rows by policy
        if trimmed.starts_with("SELECT") {
            let table = extract_table_name(&trimmed);
            if let Some(table_name) = table {
                if self.rls.is_rls_enabled(&table_name) {
                    let policies = self
                        .rls
                        .get_policies(&table_name, &crate::rls::PolicyAction::Select);
                    if policies.is_empty() {
                        // RLS enabled, no SELECT policy → deny all
                        return Err(SqlError::Execution(format!(
                            "RLS: SELECT denied on table '{}' for user '{}'",
                            table_name, user
                        )));
                    }

                    // Check if there's a public policy (USING "true")
                    let has_public = policies
                        .iter()
                        .any(|p| p.using_expr.trim().to_lowercase() == "true");

                    if !has_public {
                        // Owner-based policy: filter rows where owner column matches user
                        // Find the owner column in the result set
                        let owner_col_idx = result.columns.iter().position(|c| c == "owner");

                        if let Some(idx) = owner_col_idx {
                            result.rows.retain(|row| {
                                if let Some(crate::types::SealValue::Text(owner)) =
                                    row.values.get(idx)
                                {
                                    self.rls.check_access(
                                        &table_name,
                                        &crate::rls::PolicyAction::Select,
                                        user,
                                        Some(owner),
                                    )
                                } else {
                                    false
                                }
                            });
                        }
                        // If no owner column, check table-level access
                        else if !self.rls.check_access(
                            &table_name,
                            &crate::rls::PolicyAction::Select,
                            user,
                            None,
                        ) {
                            return Err(SqlError::Execution(format!(
                                "RLS: SELECT denied on table '{}' for user '{}'",
                                table_name, user
                            )));
                        }
                    }
                }
            }
        }

        Ok(result)
    }

    /// Set visibility for a table.
    pub fn set_visibility(&mut self, table_name: &str, visibility: Visibility) {
        self.visibility.insert(table_name.to_string(), visibility);
    }

    /// Get visibility for a table.
    pub fn get_visibility(&self, table_name: &str) -> &Visibility {
        self.visibility
            .get(table_name)
            .unwrap_or(&Visibility::Private)
    }

    /// Check if another app can read a table.
    pub fn can_read(&self, table_name: &str, requesting_app: &str) -> bool {
        match self.get_visibility(table_name) {
            Visibility::Public => true,
            Visibility::Shared { granted_apps } => {
                granted_apps.contains(&requesting_app.to_string())
            }
            Visibility::Private => false,
        }
    }

    /// List all table names in this namespace.
    pub fn table_names(&self) -> Vec<&str> {
        self.engine.table_names()
    }
}

/// Extract table name from a SQL statement (simplified parser).
fn extract_table_name(sql: &str) -> Option<String> {
    let upper = sql.to_uppercase();
    let words: Vec<&str> = upper.split_whitespace().collect();

    // INSERT INTO <table>
    if let Some(pos) = words.iter().position(|&w| w == "INTO") {
        return words.get(pos + 1).map(|s| s.to_lowercase());
    }
    // SELECT ... FROM <table>
    if let Some(pos) = words.iter().position(|&w| w == "FROM") {
        return words.get(pos + 1).map(|s| s.to_lowercase());
    }
    // UPDATE <table>
    if words.first() == Some(&"UPDATE") {
        return words.get(1).map(|s| s.to_lowercase());
    }
    // DELETE FROM <table>
    if words.first() == Some(&"DELETE") {
        if let Some(pos) = words.iter().position(|&w| w == "FROM") {
            return words.get(pos + 1).map(|s| s.to_lowercase());
        }
    }
    None
}

/// Registry of all app namespaces.
#[derive(Default)]
pub struct NamespaceRegistry {
    namespaces: HashMap<String, AppNamespace>,
}

impl NamespaceRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Deploy a new app namespace.
    pub fn deploy_app(
        &mut self,
        name: String,
        owner: String,
        schema_sql: &str,
    ) -> Result<(), SqlError> {
        if self.namespaces.contains_key(&name) {
            return Err(SqlError::Execution(format!(
                "app '{}' already exists",
                name
            )));
        }
        let mut ns = AppNamespace::new(name.clone(), owner);
        ns.deploy_schema(schema_sql)?;
        self.namespaces.insert(name, ns);
        Ok(())
    }

    /// Get a namespace by name.
    pub fn get(&self, name: &str) -> Option<&AppNamespace> {
        self.namespaces.get(name)
    }

    /// Get a mutable namespace by name.
    pub fn get_mut(&mut self, name: &str) -> Option<&mut AppNamespace> {
        self.namespaces.get_mut(name)
    }

    /// Cross-app query: read from another app's PUBLIC or SHARED table.
    /// Format: "app_name.table_name" e.g. "blog.seal.posts"
    /// Only reads (SELECT) are allowed cross-app.
    pub fn cross_app_query(
        &mut self,
        target_app: &str,
        table_name: &str,
        sql: &str,
        requesting_app: &str,
    ) -> Result<crate::engine::QueryResult, SqlError> {
        // Check the target app exists
        let target = self
            .namespaces
            .get(target_app)
            .ok_or_else(|| SqlError::Execution(format!("app '{}' not found", target_app)))?;

        // Check visibility
        if !target.can_read(table_name, requesting_app) {
            return Err(SqlError::Execution(format!(
                "access denied: '{}' cannot read '{}.{}'",
                requesting_app, target_app, table_name
            )));
        }

        // Execute the query in the target namespace
        let target = self.namespaces.get_mut(target_app).ok_or_else(|| {
            SqlError::TableNotFound(format!("namespace '{}' not found", target_app))
        })?;
        target.engine.execute(sql)
    }

    /// List all app names.
    pub fn app_names(&self) -> Vec<&str> {
        self.namespaces.keys().map(|s| s.as_str()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deploy_app() {
        let mut registry = NamespaceRegistry::new();
        registry
            .deploy_app(
                "blog.seal".into(),
                "seal1owner".into(),
                "CREATE TABLE posts (id BIGINT PRIMARY KEY, body TEXT NOT NULL)",
            )
            .unwrap();

        assert!(registry.get("blog.seal").is_some());
        let ns = registry.get("blog.seal").unwrap();
        assert_eq!(ns.owner, "seal1owner");
        assert!(ns.table_names().contains(&"posts"));
    }

    #[test]
    fn test_duplicate_app_rejected() {
        let mut registry = NamespaceRegistry::new();
        registry
            .deploy_app(
                "app.seal".into(),
                "owner".into(),
                "CREATE TABLE t (id BIGINT PRIMARY KEY)",
            )
            .unwrap();
        assert!(registry
            .deploy_app(
                "app.seal".into(),
                "owner2".into(),
                "CREATE TABLE t2 (id BIGINT PRIMARY KEY)"
            )
            .is_err());
    }

    #[test]
    fn test_execute_sql_in_namespace() {
        let mut registry = NamespaceRegistry::new();
        registry
            .deploy_app(
                "app.seal".into(),
                "owner".into(),
                "CREATE TABLE items (id BIGINT PRIMARY KEY, name TEXT NOT NULL)",
            )
            .unwrap();

        let ns = registry.get_mut("app.seal").unwrap();
        ns.execute_as("INSERT INTO items (id, name) VALUES (1, 'widget')", "owner")
            .unwrap();

        let result = ns.execute_as("SELECT * FROM items", "owner").unwrap();
        assert_eq!(result.rows.len(), 1);
    }

    #[test]
    fn test_visibility_private_default() {
        let ns = AppNamespace::new("app.seal".into(), "owner".into());
        assert_eq!(*ns.get_visibility("any_table"), Visibility::Private);
        assert!(!ns.can_read("any_table", "other_app.seal"));
    }

    #[test]
    fn test_visibility_public() {
        let mut ns = AppNamespace::new("app.seal".into(), "owner".into());
        ns.set_visibility("prices", Visibility::Public);
        assert!(ns.can_read("prices", "any_app.seal"));
    }

    #[test]
    fn test_visibility_shared() {
        let mut ns = AppNamespace::new("app.seal".into(), "owner".into());
        ns.set_visibility(
            "data",
            Visibility::Shared {
                granted_apps: vec!["partner.seal".into()],
            },
        );

        assert!(ns.can_read("data", "partner.seal"));
        assert!(!ns.can_read("data", "stranger.seal"));
    }

    #[test]
    fn test_rls_in_namespace() {
        let mut ns = AppNamespace::new("app.seal".into(), "owner".into());
        ns.deploy_schema("CREATE TABLE posts (id BIGINT PRIMARY KEY, owner TEXT, body TEXT)")
            .unwrap();

        // Enable RLS
        ns.rls.enable_rls("posts");
        ns.rls
            .add_policy(crate::rls::Policy {
                name: "owner_rw".into(),
                table_name: "posts".into(),
                action: crate::rls::PolicyAction::All,
                using_expr: "owner = CURRENT_USER()".into(),
                with_check_expr: None,
            })
            .unwrap();

        // Check access
        assert!(ns.rls.check_access(
            "posts",
            &crate::rls::PolicyAction::Select,
            "alice",
            Some("alice")
        ));
        assert!(!ns.rls.check_access(
            "posts",
            &crate::rls::PolicyAction::Select,
            "bob",
            Some("alice")
        ));
    }

    #[test]
    fn test_list_apps() {
        let mut registry = NamespaceRegistry::new();
        registry
            .deploy_app(
                "a.seal".into(),
                "o".into(),
                "CREATE TABLE t (id BIGINT PRIMARY KEY)",
            )
            .unwrap();
        registry
            .deploy_app(
                "b.seal".into(),
                "o".into(),
                "CREATE TABLE t (id BIGINT PRIMARY KEY)",
            )
            .unwrap();

        let names = registry.app_names();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"a.seal"));
        assert!(names.contains(&"b.seal"));
    }

    #[test]
    fn test_rls_blocks_select_without_policy() {
        let mut ns = AppNamespace::new("app.seal".into(), "owner".into());
        ns.deploy_schema("CREATE TABLE secrets (id BIGINT PRIMARY KEY, data TEXT)")
            .unwrap();
        ns.execute_as(
            "INSERT INTO secrets (id, data) VALUES (1, 'classified')",
            "owner",
        )
        .unwrap();

        // Enable RLS with NO policies → all access denied
        ns.rls.enable_rls("secrets");

        let result = ns.execute_as("SELECT * FROM secrets", "hacker");
        assert!(result.is_err(), "RLS should block SELECT without a policy");
    }

    #[test]
    fn test_rls_allows_select_with_public_policy() {
        let mut ns = AppNamespace::new("app.seal".into(), "owner".into());
        ns.deploy_schema("CREATE TABLE posts (id BIGINT PRIMARY KEY, body TEXT)")
            .unwrap();
        ns.execute_as("INSERT INTO posts (id, body) VALUES (1, 'hello')", "owner")
            .unwrap();

        ns.rls.enable_rls("posts");
        ns.rls
            .add_policy(crate::rls::Policy {
                name: "public_read".into(),
                table_name: "posts".into(),
                action: crate::rls::PolicyAction::Select,
                using_expr: "true".into(),
                with_check_expr: None,
            })
            .unwrap();

        // Anyone can read
        let result = ns.execute_as("SELECT * FROM posts", "anyone").unwrap();
        assert_eq!(result.rows.len(), 1);
    }

    #[test]
    fn test_rls_blocks_write_without_policy() {
        let mut ns = AppNamespace::new("app.seal".into(), "owner".into());
        ns.deploy_schema("CREATE TABLE data (id BIGINT PRIMARY KEY, val TEXT)")
            .unwrap();

        ns.rls.enable_rls("data");
        // Only add a SELECT policy, no INSERT policy
        ns.rls
            .add_policy(crate::rls::Policy {
                name: "public_read".into(),
                table_name: "data".into(),
                action: crate::rls::PolicyAction::Select,
                using_expr: "true".into(),
                with_check_expr: None,
            })
            .unwrap();

        // Write should be denied (no INSERT policy)
        let result = ns.execute_as("INSERT INTO data (id, val) VALUES (1, 'test')", "attacker");
        assert!(
            result.is_err(),
            "RLS should block INSERT without a write policy"
        );
    }

    #[test]
    fn test_rls_row_level_filtering() {
        let mut ns = AppNamespace::new("app.seal".into(), "owner".into());
        ns.deploy_schema(
            "CREATE TABLE posts (id BIGINT PRIMARY KEY, owner TEXT NOT NULL, body TEXT)",
        )
        .unwrap();

        // Insert posts by different owners
        ns.execute_as(
            "INSERT INTO posts (id, owner, body) VALUES (1, 'alice', 'alice post 1')",
            "alice",
        )
        .unwrap();
        ns.execute_as(
            "INSERT INTO posts (id, owner, body) VALUES (2, 'bob', 'bob post 1')",
            "bob",
        )
        .unwrap();
        ns.execute_as(
            "INSERT INTO posts (id, owner, body) VALUES (3, 'alice', 'alice post 2')",
            "alice",
        )
        .unwrap();
        ns.execute_as(
            "INSERT INTO posts (id, owner, body) VALUES (4, 'charlie', 'charlie post')",
            "charlie",
        )
        .unwrap();

        // Enable RLS with owner-only read policy
        ns.rls.enable_rls("posts");
        ns.rls
            .add_policy(crate::rls::Policy {
                name: "owner_read".into(),
                table_name: "posts".into(),
                action: crate::rls::PolicyAction::Select,
                using_expr: "owner = CURRENT_USER()".into(),
                with_check_expr: None,
            })
            .unwrap();

        // Alice should only see her own posts
        let result = ns.execute_as("SELECT * FROM posts", "alice").unwrap();
        assert_eq!(result.rows.len(), 2, "alice should see 2 posts");

        // Bob should only see his own posts
        let result = ns.execute_as("SELECT * FROM posts", "bob").unwrap();
        assert_eq!(result.rows.len(), 1, "bob should see 1 post");

        // Charlie should see his own post
        let result = ns.execute_as("SELECT * FROM posts", "charlie").unwrap();
        assert_eq!(result.rows.len(), 1, "charlie should see 1 post");

        // Unknown user should see nothing
        let result = ns.execute_as("SELECT * FROM posts", "nobody").unwrap();
        assert_eq!(result.rows.len(), 0, "nobody should see 0 posts");
    }

    #[test]
    fn test_rls_public_shows_all_rows() {
        let mut ns = AppNamespace::new("app.seal".into(), "owner".into());
        ns.deploy_schema("CREATE TABLE posts (id BIGINT PRIMARY KEY, owner TEXT, body TEXT)")
            .unwrap();

        ns.execute_as(
            "INSERT INTO posts (id, owner, body) VALUES (1, 'alice', 'post1')",
            "alice",
        )
        .unwrap();
        ns.execute_as(
            "INSERT INTO posts (id, owner, body) VALUES (2, 'bob', 'post2')",
            "bob",
        )
        .unwrap();

        ns.rls.enable_rls("posts");
        ns.rls
            .add_policy(crate::rls::Policy {
                name: "public".into(),
                table_name: "posts".into(),
                action: crate::rls::PolicyAction::Select,
                using_expr: "true".into(),
                with_check_expr: None,
            })
            .unwrap();

        // Public policy → everyone sees all rows
        let result = ns.execute_as("SELECT * FROM posts", "anyone").unwrap();
        assert_eq!(result.rows.len(), 2, "public policy should show all rows");
    }

    #[test]
    fn test_cross_app_query_public() {
        let mut registry = NamespaceRegistry::new();

        // Deploy app with public table
        registry
            .deploy_app(
                "blog.seal".into(),
                "owner".into(),
                "CREATE TABLE posts (id BIGINT PRIMARY KEY, body TEXT)",
            )
            .unwrap();
        let blog = registry.get_mut("blog.seal").unwrap();
        blog.set_visibility("posts", Visibility::Public);
        blog.execute_as("INSERT INTO posts (id, body) VALUES (1, 'hello')", "owner")
            .unwrap();

        // Another app queries the public table
        let result = registry
            .cross_app_query("blog.seal", "posts", "SELECT * FROM posts", "market.seal")
            .unwrap();
        assert_eq!(result.rows.len(), 1);
    }

    #[test]
    fn test_cross_app_query_private_denied() {
        let mut registry = NamespaceRegistry::new();
        registry
            .deploy_app(
                "private.seal".into(),
                "owner".into(),
                "CREATE TABLE secrets (id BIGINT PRIMARY KEY)",
            )
            .unwrap();

        // Private by default → cross-app access denied
        let result = registry.cross_app_query(
            "private.seal",
            "secrets",
            "SELECT * FROM secrets",
            "hacker.seal",
        );
        assert!(
            result.is_err(),
            "cross-app access to private table should be denied"
        );
    }

    #[test]
    fn test_cross_app_query_shared() {
        let mut registry = NamespaceRegistry::new();
        registry
            .deploy_app(
                "data.seal".into(),
                "owner".into(),
                "CREATE TABLE metrics (id BIGINT PRIMARY KEY, value BIGINT)",
            )
            .unwrap();
        let data = registry.get_mut("data.seal").unwrap();
        data.set_visibility(
            "metrics",
            Visibility::Shared {
                granted_apps: vec!["analytics.seal".into()],
            },
        );
        data.execute_as("INSERT INTO metrics (id, value) VALUES (1, 42)", "owner")
            .unwrap();

        // Granted app can read
        let result = registry
            .cross_app_query(
                "data.seal",
                "metrics",
                "SELECT * FROM metrics",
                "analytics.seal",
            )
            .unwrap();
        assert_eq!(result.rows.len(), 1);

        // Non-granted app cannot
        let result = registry.cross_app_query(
            "data.seal",
            "metrics",
            "SELECT * FROM metrics",
            "stranger.seal",
        );
        assert!(result.is_err());
    }
}
