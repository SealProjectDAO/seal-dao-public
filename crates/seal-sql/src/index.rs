//! SQL index support using persistent red-black trees.
//!
//! When a CREATE INDEX is executed, we build an RBTree mapping
//! column values to row indices. This accelerates WHERE clause
//! lookups from O(n) table scan to O(log n) tree lookup.

use seal_merkle::rbtree::RBTree;
use std::collections::HashMap;

/// An index on a single column.
#[derive(Clone)]
pub struct ColumnIndex {
    /// Column name this index covers.
    pub column_name: String,
    /// RBTree mapping column value (as string) → row indices.
    tree: RBTree<String, Vec<usize>>,
}

impl ColumnIndex {
    /// Create a new empty index for a column.
    pub fn new(column_name: String) -> Self {
        ColumnIndex {
            column_name,
            tree: RBTree::new(),
        }
    }

    /// Insert a value→row_index mapping.
    pub fn insert(&mut self, value: String, row_idx: usize) {
        let existing = self.tree.get(&value).cloned().unwrap_or_default();
        let mut rows = existing;
        if !rows.contains(&row_idx) {
            rows.push(row_idx);
        }
        self.tree = self.tree.insert(value, rows);
    }

    /// Lookup row indices for an exact value match.
    pub fn lookup_eq(&self, value: &str) -> Vec<usize> {
        self.tree
            .get(&value.to_string())
            .cloned()
            .unwrap_or_default()
    }

    /// Range query: row indices where min_val <= value <= max_val.
    pub fn lookup_range(&self, min_val: &str, max_val: &str) -> Vec<usize> {
        let entries = self.tree.range(&min_val.to_string(), &max_val.to_string());
        entries.into_iter().flat_map(|(_, rows)| rows).collect()
    }

    /// Number of distinct values indexed.
    pub fn distinct_count(&self) -> usize {
        self.tree.len()
    }
}

/// Manages indexes for all tables.
#[derive(Default, Clone)]
pub struct IndexManager {
    /// Indexes keyed by "table.column".
    indexes: HashMap<String, ColumnIndex>,
}

impl IndexManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an index on a column.
    pub fn create_index(&mut self, table: &str, column: &str) {
        let key = format!("{}.{}", table, column);
        self.indexes
            .entry(key)
            .or_insert_with(|| ColumnIndex::new(column.to_string()));
    }

    /// Get an index for a table.column.
    pub fn get_index(&self, table: &str, column: &str) -> Option<&ColumnIndex> {
        let key = format!("{}.{}", table, column);
        self.indexes.get(&key)
    }

    /// Get mutable index for a table.column.
    pub fn get_index_mut(&mut self, table: &str, column: &str) -> Option<&mut ColumnIndex> {
        let key = format!("{}.{}", table, column);
        self.indexes.get_mut(&key)
    }

    /// Check if an index exists.
    pub fn has_index(&self, table: &str, column: &str) -> bool {
        let key = format!("{}.{}", table, column);
        self.indexes.contains_key(&key)
    }

    /// Rebuild an index from table data.
    pub fn rebuild_index(
        &mut self,
        table: &str,
        column: &str,
        values: &[(String, usize)], // (value, row_idx)
    ) {
        let key = format!("{}.{}", table, column);
        let mut index = ColumnIndex::new(column.to_string());
        for (val, row_idx) in values {
            index.insert(val.clone(), *row_idx);
        }
        self.indexes.insert(key, index);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_column_index_basic() {
        let mut idx = ColumnIndex::new("name".into());
        idx.insert("alice".into(), 0);
        idx.insert("bob".into(), 1);
        idx.insert("alice".into(), 2); // Second alice

        assert_eq!(idx.lookup_eq("alice"), vec![0, 2]);
        assert_eq!(idx.lookup_eq("bob"), vec![1]);
        assert_eq!(idx.lookup_eq("charlie"), Vec::<usize>::new());
        assert_eq!(idx.distinct_count(), 2);
    }

    #[test]
    fn test_range_query() {
        let mut idx = ColumnIndex::new("score".into());
        for i in 0..10 {
            idx.insert(format!("{:03}", i * 10), i);
        }

        let range = idx.lookup_range("030", "070");
        assert!(range.contains(&3)); // 030
        assert!(range.contains(&5)); // 050
        assert!(range.contains(&7)); // 070
        assert!(!range.contains(&2)); // 020 < 030
        assert!(!range.contains(&8)); // 080 > 070
    }

    #[test]
    fn test_index_manager() {
        let mut mgr = IndexManager::new();
        mgr.create_index("users", "name");
        assert!(mgr.has_index("users", "name"));
        assert!(!mgr.has_index("users", "email"));

        let idx = mgr.get_index_mut("users", "name").unwrap();
        idx.insert("alice".into(), 0);
        idx.insert("bob".into(), 1);

        let idx = mgr.get_index("users", "name").unwrap();
        assert_eq!(idx.lookup_eq("alice"), vec![0]);
    }

    #[test]
    fn test_rebuild_index() {
        let mut mgr = IndexManager::new();
        let data = vec![("alice".into(), 0), ("bob".into(), 1), ("alice".into(), 2)];
        mgr.rebuild_index("users", "name", &data);

        let idx = mgr.get_index("users", "name").unwrap();
        assert_eq!(idx.lookup_eq("alice"), vec![0, 2]);
        assert_eq!(idx.lookup_eq("bob"), vec![1]);
    }
}
