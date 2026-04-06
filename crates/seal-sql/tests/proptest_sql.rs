//! Property tests for the SQL engine.

use proptest::prelude::*;
use seal_sql::engine::Engine;
use seal_sql::types::SealValue;

/// Generate a random valid table name.
fn arb_table_name() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9_]{2,8}".prop_map(|s| s)
}

proptest! {
    /// Property: CREATE TABLE then SELECT * returns 0 rows.
    #[test]
    fn prop_create_then_select_empty(table in arb_table_name()) {
        let mut engine = Engine::new();
        let create = format!("CREATE TABLE {} (id BIGINT PRIMARY KEY, val TEXT)", table);
        engine.execute(&create).unwrap();
        let result = engine.execute(&format!("SELECT * FROM {}", table)).unwrap();
        prop_assert_eq!(result.rows.len(), 0);
    }

    /// Property: INSERT then SELECT returns the inserted row.
    #[test]
    fn prop_insert_then_select(
        table in arb_table_name(),
        id in 1i64..10000,
        val in "[a-z]{1,20}",
    ) {
        let mut engine = Engine::new();
        engine.execute(&format!(
            "CREATE TABLE {} (id BIGINT PRIMARY KEY, val TEXT)", table
        )).unwrap();
        engine.execute(&format!(
            "INSERT INTO {} (id, val) VALUES ({}, '{}')", table, id, val
        )).unwrap();
        let result = engine.execute(&format!("SELECT * FROM {}", table)).unwrap();
        prop_assert_eq!(result.rows.len(), 1);
        prop_assert_eq!(&result.rows[0].values[0], &SealValue::BigInt(id));
        prop_assert_eq!(&result.rows[0].values[1], &SealValue::Text(val));
    }

    /// Property: DELETE removes the row, SELECT returns empty.
    #[test]
    fn prop_insert_delete_empty(
        table in arb_table_name(),
        id in 1i64..10000,
    ) {
        let mut engine = Engine::new();
        engine.execute(&format!(
            "CREATE TABLE {} (id BIGINT PRIMARY KEY, val TEXT)", table
        )).unwrap();
        engine.execute(&format!(
            "INSERT INTO {} (id, val) VALUES ({}, 'x')", table, id
        )).unwrap();
        engine.execute(&format!(
            "DELETE FROM {} WHERE id = {}", table, id
        )).unwrap();
        let result = engine.execute(&format!("SELECT * FROM {}", table)).unwrap();
        prop_assert_eq!(result.rows.len(), 0);
    }

    /// Property: UPDATE changes the value, SELECT returns new value.
    #[test]
    fn prop_update_changes_value(
        table in arb_table_name(),
        id in 1i64..10000,
        old_val in "[a-z]{1,10}",
        new_val in "[a-z]{1,10}",
    ) {
        let mut engine = Engine::new();
        engine.execute(&format!(
            "CREATE TABLE {} (id BIGINT PRIMARY KEY, val TEXT)", table
        )).unwrap();
        engine.execute(&format!(
            "INSERT INTO {} (id, val) VALUES ({}, '{}')", table, id, old_val
        )).unwrap();
        engine.execute(&format!(
            "UPDATE {} SET val = '{}' WHERE id = {}", table, new_val, id
        )).unwrap();
        let result = engine.execute(&format!(
            "SELECT * FROM {} WHERE id = {}", table, id
        )).unwrap();
        prop_assert_eq!(result.rows.len(), 1);
        prop_assert_eq!(&result.rows[0].values[1], &SealValue::Text(new_val));
    }

    /// Property: state_root is deterministic — same ops produce same root.
    #[test]
    fn prop_state_root_deterministic(
        id1 in 1i64..100,
        id2 in 101i64..200,
        val1 in "[a-z]{1,5}",
        val2 in "[a-z]{1,5}",
    ) {
        let mut e1 = Engine::new();
        let mut e2 = Engine::new();

        for e in [&mut e1, &mut e2] {
            e.execute("CREATE TABLE t (id BIGINT PRIMARY KEY, val TEXT)").unwrap();
            e.execute(&format!("INSERT INTO t (id, val) VALUES ({}, '{}')", id1, val1)).unwrap();
            e.execute(&format!("INSERT INTO t (id, val) VALUES ({}, '{}')", id2, val2)).unwrap();
        }

        prop_assert_eq!(e1.state_root(), e2.state_root());
    }
}
