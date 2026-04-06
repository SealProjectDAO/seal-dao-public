//! Persistent red-black tree for ordered indexes.
//!
//! Okasaki-style purely functional red-black tree. Every modification
//! returns a new tree, sharing unchanged nodes with the original.
//!
//! Used for SQL WHERE clause acceleration on indexed columns.
//! All operations are O(log n).
//!
//! Reference: Okasaki (1998), Chapter 3.3.
//! Verified implementation: Appel (2011), "Efficient Verified Red-Black Trees".

use std::sync::Arc;

/// Color of a red-black tree node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Color {
    Red,
    Black,
}

/// A persistent red-black tree node.
#[derive(Clone, Debug)]
enum RBNode<K: Clone + Ord, V: Clone> {
    Leaf,
    Node {
        color: Color,
        left: Arc<RBNode<K, V>>,
        key: K,
        value: V,
        right: Arc<RBNode<K, V>>,
    },
}

/// A persistent ordered map backed by a red-black tree.
#[derive(Clone, Debug)]
pub struct RBTree<K: Clone + Ord, V: Clone> {
    root: Arc<RBNode<K, V>>,
    len: usize,
}

impl<K: Clone + Ord, V: Clone> RBTree<K, V> {
    /// Create an empty tree.
    pub fn new() -> Self {
        RBTree {
            root: Arc::new(RBNode::Leaf),
            len: 0,
        }
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Is the tree empty?
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Look up a value by key.
    pub fn get(&self, key: &K) -> Option<&V> {
        get_recursive(&self.root, key)
    }

    /// Insert a key-value pair. Returns a NEW tree (old tree unchanged).
    pub fn insert(&self, key: K, value: V) -> Self {
        let new_root = insert_recursive(&self.root, key.clone(), value);
        // Root must be black (red-black invariant)
        let blackened = match new_root.as_ref() {
            RBNode::Node {
                left,
                key: k,
                value: v,
                right,
                ..
            } => Arc::new(RBNode::Node {
                color: Color::Black,
                left: left.clone(),
                key: k.clone(),
                value: v.clone(),
                right: right.clone(),
            }),
            RBNode::Leaf => new_root,
        };
        let was_new = self.get(&key).is_none();
        RBTree {
            root: blackened,
            len: if was_new { self.len + 1 } else { self.len },
        }
    }

    /// Check if a key exists.
    pub fn contains_key(&self, key: &K) -> bool {
        self.get(key).is_some()
    }

    /// Collect all entries in sorted order.
    pub fn to_vec(&self) -> Vec<(K, V)> {
        let mut result = Vec::new();
        collect_sorted(&self.root, &mut result);
        result
    }

    /// Get the minimum key.
    pub fn min(&self) -> Option<(&K, &V)> {
        min_recursive(&self.root)
    }

    /// Get the maximum key.
    pub fn max(&self) -> Option<(&K, &V)> {
        max_recursive(&self.root)
    }

    /// Range query: all entries with min_key <= key <= max_key.
    pub fn range(&self, min_key: &K, max_key: &K) -> Vec<(K, V)> {
        let mut result = Vec::new();
        range_recursive(&self.root, min_key, max_key, &mut result);
        result
    }
}

impl<K: Clone + Ord, V: Clone> Default for RBTree<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

fn get_recursive<'a, K: Clone + Ord, V: Clone>(
    node: &'a Arc<RBNode<K, V>>,
    key: &K,
) -> Option<&'a V> {
    match node.as_ref() {
        RBNode::Leaf => None,
        RBNode::Node {
            left,
            key: k,
            value,
            right,
            ..
        } => match key.cmp(k) {
            std::cmp::Ordering::Less => get_recursive(left, key),
            std::cmp::Ordering::Equal => Some(value),
            std::cmp::Ordering::Greater => get_recursive(right, key),
        },
    }
}

fn insert_recursive<K: Clone + Ord, V: Clone>(
    node: &Arc<RBNode<K, V>>,
    key: K,
    value: V,
) -> Arc<RBNode<K, V>> {
    match node.as_ref() {
        RBNode::Leaf => Arc::new(RBNode::Node {
            color: Color::Red,
            left: Arc::new(RBNode::Leaf),
            key,
            value,
            right: Arc::new(RBNode::Leaf),
        }),
        RBNode::Node {
            color,
            left,
            key: k,
            value: v,
            right,
        } => {
            let new_node = match key.cmp(k) {
                std::cmp::Ordering::Less => RBNode::Node {
                    color: *color,
                    left: insert_recursive(left, key, value),
                    key: k.clone(),
                    value: v.clone(),
                    right: right.clone(),
                },
                std::cmp::Ordering::Equal => RBNode::Node {
                    color: *color,
                    left: left.clone(),
                    key,
                    value,
                    right: right.clone(),
                },
                std::cmp::Ordering::Greater => RBNode::Node {
                    color: *color,
                    left: left.clone(),
                    key: k.clone(),
                    value: v.clone(),
                    right: insert_recursive(right, key, value),
                },
            };
            balance(new_node)
        }
    }
}

/// Okasaki's balance function — restores red-black invariants after insert.
fn balance<K: Clone + Ord, V: Clone>(node: RBNode<K, V>) -> Arc<RBNode<K, V>> {
    // Four cases of red-red violation that need rebalancing
    match node {
        // Case 1: Black(Red(Red(a,x,b),y,c),z,d)
        RBNode::Node {
            color: Color::Black,
            ref left,
            key: ref z_key,
            value: ref z_val,
            ref right,
        } if matches!(
            left.as_ref(),
            RBNode::Node {
                color: Color::Red,
                ..
            }
        ) =>
        {
            if let RBNode::Node {
                color: Color::Red,
                left: ref y_left,
                key: ref y_key,
                value: ref y_val,
                right: ref y_right,
            } = left.as_ref()
            {
                if let RBNode::Node {
                    color: Color::Red,
                    left: ref a,
                    key: ref x_key,
                    value: ref x_val,
                    right: ref b,
                } = y_left.as_ref()
                {
                    return Arc::new(RBNode::Node {
                        color: Color::Red,
                        left: Arc::new(RBNode::Node {
                            color: Color::Black,
                            left: a.clone(),
                            key: x_key.clone(),
                            value: x_val.clone(),
                            right: b.clone(),
                        }),
                        key: y_key.clone(),
                        value: y_val.clone(),
                        right: Arc::new(RBNode::Node {
                            color: Color::Black,
                            left: y_right.clone(),
                            key: z_key.clone(),
                            value: z_val.clone(),
                            right: right.clone(),
                        }),
                    });
                }
                // Case 2: Black(Red(a,x,Red(b,y,c)),z,d)
                if let RBNode::Node {
                    color: Color::Red,
                    left: ref b,
                    key: ref y2_key,
                    value: ref y2_val,
                    right: ref c,
                } = y_right.as_ref()
                {
                    return Arc::new(RBNode::Node {
                        color: Color::Red,
                        left: Arc::new(RBNode::Node {
                            color: Color::Black,
                            left: y_left.clone(),
                            key: y_key.clone(),
                            value: y_val.clone(),
                            right: b.clone(),
                        }),
                        key: y2_key.clone(),
                        value: y2_val.clone(),
                        right: Arc::new(RBNode::Node {
                            color: Color::Black,
                            left: c.clone(),
                            key: z_key.clone(),
                            value: z_val.clone(),
                            right: right.clone(),
                        }),
                    });
                }
            }
            Arc::new(node)
        }
        // Cases 3 & 4: mirror of above on the right side
        RBNode::Node {
            color: Color::Black,
            ref left,
            key: ref x_key,
            value: ref x_val,
            ref right,
        } if matches!(
            right.as_ref(),
            RBNode::Node {
                color: Color::Red,
                ..
            }
        ) =>
        {
            if let RBNode::Node {
                color: Color::Red,
                left: ref y_left,
                key: ref y_key,
                value: ref y_val,
                right: ref y_right,
            } = right.as_ref()
            {
                // Case 3
                if let RBNode::Node {
                    color: Color::Red,
                    left: ref b,
                    key: ref z_key,
                    value: ref z_val,
                    right: ref d,
                } = y_right.as_ref()
                {
                    return Arc::new(RBNode::Node {
                        color: Color::Red,
                        left: Arc::new(RBNode::Node {
                            color: Color::Black,
                            left: left.clone(),
                            key: x_key.clone(),
                            value: x_val.clone(),
                            right: y_left.clone(),
                        }),
                        key: y_key.clone(),
                        value: y_val.clone(),
                        right: Arc::new(RBNode::Node {
                            color: Color::Black,
                            left: b.clone(),
                            key: z_key.clone(),
                            value: z_val.clone(),
                            right: d.clone(),
                        }),
                    });
                }
                // Case 4
                if let RBNode::Node {
                    color: Color::Red,
                    left: ref b,
                    key: ref y2_key,
                    value: ref y2_val,
                    right: ref c,
                } = y_left.as_ref()
                {
                    return Arc::new(RBNode::Node {
                        color: Color::Red,
                        left: Arc::new(RBNode::Node {
                            color: Color::Black,
                            left: left.clone(),
                            key: x_key.clone(),
                            value: x_val.clone(),
                            right: b.clone(),
                        }),
                        key: y2_key.clone(),
                        value: y2_val.clone(),
                        right: Arc::new(RBNode::Node {
                            color: Color::Black,
                            left: c.clone(),
                            key: y_key.clone(),
                            value: y_val.clone(),
                            right: y_right.clone(),
                        }),
                    });
                }
            }
            Arc::new(node)
        }
        _ => Arc::new(node),
    }
}

fn collect_sorted<K: Clone + Ord, V: Clone>(node: &Arc<RBNode<K, V>>, result: &mut Vec<(K, V)>) {
    match node.as_ref() {
        RBNode::Leaf => {}
        RBNode::Node {
            left,
            key,
            value,
            right,
            ..
        } => {
            collect_sorted(left, result);
            result.push((key.clone(), value.clone()));
            collect_sorted(right, result);
        }
    }
}

fn min_recursive<'a, K: Clone + Ord, V: Clone>(
    node: &'a Arc<RBNode<K, V>>,
) -> Option<(&'a K, &'a V)> {
    match node.as_ref() {
        RBNode::Leaf => None,
        RBNode::Node {
            left, key, value, ..
        } => min_recursive(left).or(Some((key, value))),
    }
}

fn max_recursive<'a, K: Clone + Ord, V: Clone>(
    node: &'a Arc<RBNode<K, V>>,
) -> Option<(&'a K, &'a V)> {
    match node.as_ref() {
        RBNode::Leaf => None,
        RBNode::Node {
            key, value, right, ..
        } => max_recursive(right).or(Some((key, value))),
    }
}

fn range_recursive<K: Clone + Ord, V: Clone>(
    node: &Arc<RBNode<K, V>>,
    min_key: &K,
    max_key: &K,
    result: &mut Vec<(K, V)>,
) {
    match node.as_ref() {
        RBNode::Leaf => {}
        RBNode::Node {
            left,
            key,
            value,
            right,
            ..
        } => {
            if key >= min_key {
                range_recursive(left, min_key, max_key, result);
            }
            if key >= min_key && key <= max_key {
                result.push((key.clone(), value.clone()));
            }
            if key <= max_key {
                range_recursive(right, min_key, max_key, result);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty() {
        let tree: RBTree<i32, String> = RBTree::new();
        assert!(tree.is_empty());
        assert_eq!(tree.len(), 0);
        assert!(tree.get(&1).is_none());
    }

    #[test]
    fn test_insert_and_get() {
        let tree = RBTree::new().insert(3, "c").insert(1, "a").insert(2, "b");

        assert_eq!(tree.len(), 3);
        assert_eq!(tree.get(&1), Some(&"a"));
        assert_eq!(tree.get(&2), Some(&"b"));
        assert_eq!(tree.get(&3), Some(&"c"));
        assert_eq!(tree.get(&4), None);
    }

    #[test]
    fn test_sorted_order() {
        let tree = RBTree::new()
            .insert(5, "e")
            .insert(3, "c")
            .insert(1, "a")
            .insert(4, "d")
            .insert(2, "b");

        let entries = tree.to_vec();
        let keys: Vec<i32> = entries.iter().map(|(k, _)| *k).collect();
        assert_eq!(keys, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_persistence() {
        let tree1 = RBTree::new().insert(1, "a").insert(2, "b");
        let tree2 = tree1.insert(3, "c");

        // tree1 is unchanged (persistent)
        assert_eq!(tree1.len(), 2);
        assert!(tree1.get(&3).is_none());

        // tree2 has the new entry
        assert_eq!(tree2.len(), 3);
        assert_eq!(tree2.get(&3), Some(&"c"));
    }

    #[test]
    fn test_overwrite() {
        let tree = RBTree::new().insert(1, "old").insert(1, "new");
        assert_eq!(tree.len(), 1);
        assert_eq!(tree.get(&1), Some(&"new"));
    }

    #[test]
    fn test_range_query() {
        let tree = RBTree::new()
            .insert(1, "a")
            .insert(3, "c")
            .insert(5, "e")
            .insert(7, "g")
            .insert(9, "i");

        let range = tree.range(&3, &7);
        let keys: Vec<i32> = range.iter().map(|(k, _)| *k).collect();
        assert_eq!(keys, vec![3, 5, 7]);
    }

    #[test]
    fn test_min_max() {
        let tree = RBTree::new().insert(5, "e").insert(1, "a").insert(9, "i");

        assert_eq!(tree.min(), Some((&1, &"a")));
        assert_eq!(tree.max(), Some((&9, &"i")));
    }

    #[test]
    fn test_many_inserts() {
        let mut tree = RBTree::new();
        for i in 0..1000 {
            tree = tree.insert(i, i * 10);
        }
        assert_eq!(tree.len(), 1000);

        // All entries retrievable
        for i in 0..1000 {
            assert_eq!(tree.get(&i), Some(&(i * 10)));
        }

        // Sorted order
        let entries = tree.to_vec();
        for i in 1..entries.len() {
            assert!(entries[i - 1].0 < entries[i].0);
        }
    }
}
