//! Persistent (functional) red-black tree for SQL secondary indexes.
//!
//! Left-leaning red-black tree (LLRB) variant. Every mutation returns a
//! **new** tree; the old tree remains valid and shares structure with
//! the new one via `Rc<Node>`.
//!
//! All operations are O(log n):
//! - `insert` / `remove` return new trees with structural sharing
//! - `get` returns a reference into the existing tree
//! - `range` collects entries in a key range
//!
//! Reference: Sedgewick (2008), "Left-leaning Red-Black Trees".

use std::rc::Rc;

// ---------------------------------------------------------------------------
// Color
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Color {
    Red,
    Black,
}

// ---------------------------------------------------------------------------
// Node
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct Node<K: Ord + Clone, V: Clone> {
    color: Color,
    key: K,
    value: V,
    left: Option<Rc<Node<K, V>>>,
    right: Option<Rc<Node<K, V>>>,
}

/// Returns `true` when `link` is a red node.
fn is_red<K: Ord + Clone, V: Clone>(link: &Option<Rc<Node<K, V>>>) -> bool {
    match link {
        Some(n) => n.color == Color::Red,
        None => false,
    }
}

// ---------------------------------------------------------------------------
// Rotations & color-flip (all produce new nodes, never mutate)
// ---------------------------------------------------------------------------

/// Rotate a right-leaning red link to the left.
fn rotate_left<K: Ord + Clone, V: Clone>(h: Rc<Node<K, V>>) -> Rc<Node<K, V>> {
    // h.right must be Some and Red — caller guarantees this
    let x = match h.right {
        Some(ref r) => r.clone(),
        None => return h,
    };
    Rc::new(Node {
        color: h.color,
        key: x.key.clone(),
        value: x.value.clone(),
        left: Some(Rc::new(Node {
            color: Color::Red,
            key: h.key.clone(),
            value: h.value.clone(),
            left: h.left.clone(),
            right: x.left.clone(),
        })),
        right: x.right.clone(),
    })
}

/// Rotate a left-leaning red link to the right.
fn rotate_right<K: Ord + Clone, V: Clone>(h: Rc<Node<K, V>>) -> Rc<Node<K, V>> {
    let x = match h.left {
        Some(ref l) => l.clone(),
        None => return h,
    };
    Rc::new(Node {
        color: h.color,
        key: x.key.clone(),
        value: x.value.clone(),
        left: x.left.clone(),
        right: Some(Rc::new(Node {
            color: Color::Red,
            key: h.key.clone(),
            value: h.value.clone(),
            left: x.right.clone(),
            right: h.right.clone(),
        })),
    })
}

/// Flip the colors of a node and its two children.
fn flip_colors<K: Ord + Clone, V: Clone>(h: Rc<Node<K, V>>) -> Rc<Node<K, V>> {
    let flip = |c: Color| -> Color {
        match c {
            Color::Red => Color::Black,
            Color::Black => Color::Red,
        }
    };
    let new_left = h.left.as_ref().map(|l| {
        Rc::new(Node {
            color: flip(l.color),
            key: l.key.clone(),
            value: l.value.clone(),
            left: l.left.clone(),
            right: l.right.clone(),
        })
    });
    let new_right = h.right.as_ref().map(|r| {
        Rc::new(Node {
            color: flip(r.color),
            key: r.key.clone(),
            value: r.value.clone(),
            left: r.left.clone(),
            right: r.right.clone(),
        })
    });
    Rc::new(Node {
        color: flip(h.color),
        key: h.key.clone(),
        value: h.value.clone(),
        left: new_left,
        right: new_right,
    })
}

// ---------------------------------------------------------------------------
// LLRB fixup
// ---------------------------------------------------------------------------

/// Restore LLRB invariants after an insert or delete on `h`.
fn fixup<K: Ord + Clone, V: Clone>(mut h: Rc<Node<K, V>>) -> Rc<Node<K, V>> {
    // Right-leaning red link -> rotate left
    if is_red(&h.right) && !is_red(&h.left) {
        h = rotate_left(h);
    }
    // Two consecutive left-leaning red links -> rotate right
    if is_red(&h.left) && is_red(&h.left.as_ref().and_then(|l| l.left.clone())) {
        h = rotate_right(h);
    }
    // Both children red -> flip colors (split 4-node)
    if is_red(&h.left) && is_red(&h.right) {
        h = flip_colors(h);
    }
    h
}

// ---------------------------------------------------------------------------
// Insert
// ---------------------------------------------------------------------------

/// Recursive insert. Returns `(new_subtree, was_new_key)`.
fn insert_rec<K: Ord + Clone, V: Clone>(
    link: &Option<Rc<Node<K, V>>>,
    key: K,
    value: V,
) -> (Rc<Node<K, V>>, bool) {
    let node = match link {
        None => {
            return (
                Rc::new(Node {
                    color: Color::Red,
                    key,
                    value,
                    left: None,
                    right: None,
                }),
                true,
            );
        }
        Some(n) => n,
    };

    let (new_node, was_new) = match key.cmp(&node.key) {
        std::cmp::Ordering::Less => {
            let (new_left, is_new) = insert_rec(&node.left, key, value);
            (
                Rc::new(Node {
                    color: node.color,
                    key: node.key.clone(),
                    value: node.value.clone(),
                    left: Some(new_left),
                    right: node.right.clone(),
                }),
                is_new,
            )
        }
        std::cmp::Ordering::Equal => (
            Rc::new(Node {
                color: node.color,
                key,
                value,
                left: node.left.clone(),
                right: node.right.clone(),
            }),
            false,
        ),
        std::cmp::Ordering::Greater => {
            let (new_right, is_new) = insert_rec(&node.right, key, value);
            (
                Rc::new(Node {
                    color: node.color,
                    key: node.key.clone(),
                    value: node.value.clone(),
                    left: node.left.clone(),
                    right: Some(new_right),
                }),
                is_new,
            )
        }
    };

    (fixup(new_node), was_new)
}

// ---------------------------------------------------------------------------
// Delete helpers
// ---------------------------------------------------------------------------

/// Move a red link to the left child.
fn move_red_left<K: Ord + Clone, V: Clone>(mut h: Rc<Node<K, V>>) -> Rc<Node<K, V>> {
    h = flip_colors(h);
    // If h.right.left is red, rotate
    if let Some(ref r) = h.right {
        if is_red(&r.left) {
            let new_right = rotate_right(r.clone());
            h = Rc::new(Node {
                color: h.color,
                key: h.key.clone(),
                value: h.value.clone(),
                left: h.left.clone(),
                right: Some(new_right),
            });
            h = rotate_left(h);
            h = flip_colors(h);
        }
    }
    h
}

/// Move a red link to the right child.
fn move_red_right<K: Ord + Clone, V: Clone>(mut h: Rc<Node<K, V>>) -> Rc<Node<K, V>> {
    h = flip_colors(h);
    if let Some(ref l) = h.left {
        if is_red(&l.left) {
            h = rotate_right(h);
            h = flip_colors(h);
        }
    }
    h
}

/// Find the minimum node in a subtree.
fn min_node<K: Ord + Clone, V: Clone>(node: &Rc<Node<K, V>>) -> &Rc<Node<K, V>> {
    match node.left {
        Some(ref l) => min_node(l),
        None => node,
    }
}

/// Delete the minimum key from a subtree.
fn delete_min_rec<K: Ord + Clone, V: Clone>(
    h: Rc<Node<K, V>>,
) -> Option<Rc<Node<K, V>>> {
    if h.left.is_none() {
        return None; // h is the minimum; remove it
    }

    let mut h = h;

    if !is_red(&h.left) && !is_red(&h.left.as_ref().and_then(|l| l.left.clone())) {
        h = move_red_left(h);
    }

    let new_left = match h.left {
        Some(ref l) => delete_min_rec(l.clone()),
        None => None,
    };

    let result = Rc::new(Node {
        color: h.color,
        key: h.key.clone(),
        value: h.value.clone(),
        left: new_left,
        right: h.right.clone(),
    });

    Some(fixup(result))
}

/// Recursive delete. Returns `(Option<new_subtree>, key_was_found)`.
fn delete_rec<K: Ord + Clone, V: Clone>(
    link: &Option<Rc<Node<K, V>>>,
    key: &K,
) -> (Option<Rc<Node<K, V>>>, bool) {
    let node = match link {
        None => return (None, false),
        Some(n) => n.clone(),
    };

    let mut h = node;

    if *key < h.key {
        // Go left
        if !is_red(&h.left) && !is_red(&h.left.as_ref().and_then(|l| l.left.clone())) {
            h = move_red_left(h);
        }
        let (new_left, found) = delete_rec(&h.left, key);
        let result = Rc::new(Node {
            color: h.color,
            key: h.key.clone(),
            value: h.value.clone(),
            left: new_left,
            right: h.right.clone(),
        });
        (Some(fixup(result)), found)
    } else {
        if is_red(&h.left) {
            h = rotate_right(h);
        }

        // Found at bottom — this is the node to delete and it has no right child
        if *key == h.key && h.right.is_none() {
            return (None, true);
        }

        if !is_red(&h.right) && !is_red(&h.right.as_ref().and_then(|r| r.left.clone())) {
            h = move_red_right(h);
        }

        if *key == h.key {
            // Replace with successor (min of right subtree)
            let successor = match h.right {
                Some(ref r) => min_node(r).clone(),
                None => return (None, true),
            };
            let new_right = match h.right {
                Some(ref r) => delete_min_rec(r.clone()),
                None => None,
            };
            let result = Rc::new(Node {
                color: h.color,
                key: successor.key.clone(),
                value: successor.value.clone(),
                left: h.left.clone(),
                right: new_right,
            });
            (Some(fixup(result)), true)
        } else {
            // Go right
            let (new_right, found) = delete_rec(&h.right, key);
            let result = Rc::new(Node {
                color: h.color,
                key: h.key.clone(),
                value: h.value.clone(),
                left: h.left.clone(),
                right: new_right,
            });
            (Some(fixup(result)), found)
        }
    }
}

// ---------------------------------------------------------------------------
// Lookup
// ---------------------------------------------------------------------------

fn get_rec<'a, K: Ord + Clone, V: Clone>(
    link: &'a Option<Rc<Node<K, V>>>,
    key: &K,
) -> Option<&'a V> {
    let node = match link {
        None => return None,
        Some(n) => n,
    };
    match key.cmp(&node.key) {
        std::cmp::Ordering::Less => get_rec(&node.left, key),
        std::cmp::Ordering::Equal => Some(&node.value),
        std::cmp::Ordering::Greater => get_rec(&node.right, key),
    }
}

// ---------------------------------------------------------------------------
// Range query
// ---------------------------------------------------------------------------

fn range_rec<'a, K: Ord + Clone, V: Clone>(
    link: &'a Option<Rc<Node<K, V>>>,
    from: &K,
    to: &K,
    out: &mut Vec<(&'a K, &'a V)>,
) {
    let node = match link {
        None => return,
        Some(n) => n,
    };
    if node.key > *from {
        range_rec(&node.left, from, to, out);
    }
    if node.key >= *from && node.key <= *to {
        out.push((&node.key, &node.value));
    }
    if node.key < *to {
        range_rec(&node.right, from, to, out);
    }
}

// ---------------------------------------------------------------------------
// Min / Max
// ---------------------------------------------------------------------------

fn min_ref<'a, K: Ord + Clone, V: Clone>(
    link: &'a Option<Rc<Node<K, V>>>,
) -> Option<(&'a K, &'a V)> {
    let node = link.as_ref()?;
    min_ref(&node.left).or(Some((&node.key, &node.value)))
}

fn max_ref<'a, K: Ord + Clone, V: Clone>(
    link: &'a Option<Rc<Node<K, V>>>,
) -> Option<(&'a K, &'a V)> {
    let node = link.as_ref()?;
    max_ref(&node.right).or(Some((&node.key, &node.value)))
}

// ---------------------------------------------------------------------------
// In-order traversal iterator
// ---------------------------------------------------------------------------

/// Collects nodes into a vector for iteration. We store references into the
/// tree, which is safe because the `Rc` nodes keep everything alive as long
/// as the tree is alive.
fn collect_refs<'a, K: Ord + Clone, V: Clone>(
    link: &'a Option<Rc<Node<K, V>>>,
    out: &mut Vec<(&'a K, &'a V)>,
) {
    let node = match link {
        None => return,
        Some(n) => n,
    };
    collect_refs(&node.left, out);
    out.push((&node.key, &node.value));
    collect_refs(&node.right, out);
}

// ---------------------------------------------------------------------------
// Size counting (for verification)
// ---------------------------------------------------------------------------

#[cfg(test)]
fn count_nodes<K: Ord + Clone, V: Clone>(link: &Option<Rc<Node<K, V>>>) -> usize {
    match link {
        None => 0,
        Some(n) => 1 + count_nodes(&n.left) + count_nodes(&n.right),
    }
}

// ---------------------------------------------------------------------------
// RBTree public API
// ---------------------------------------------------------------------------

/// A persistent (functional) red-black tree.
///
/// Every mutation (`insert`, `remove`) returns a **new** tree. The original
/// tree remains valid and shares unchanged nodes with the new version via
/// `Rc<Node>`.
///
/// This is designed for SQL secondary indexes where multiple transaction
/// snapshots may reference different versions of the same index.
#[derive(Clone, Debug)]
pub struct RBTree<K: Ord + Clone, V: Clone> {
    root: Option<Rc<Node<K, V>>>,
    len: usize,
}

impl<K: Ord + Clone, V: Clone> RBTree<K, V> {
    /// Create an empty tree.
    pub fn new() -> Self {
        RBTree {
            root: None,
            len: 0,
        }
    }

    /// Insert a key-value pair, returning a new tree.
    ///
    /// If the key already exists, its value is replaced. The old tree is
    /// unmodified.
    pub fn insert(&self, key: K, value: V) -> Self {
        let (new_root, was_new) = insert_rec(&self.root, key, value);
        // Root must always be black.
        let blackened = Rc::new(Node {
            color: Color::Black,
            key: new_root.key.clone(),
            value: new_root.value.clone(),
            left: new_root.left.clone(),
            right: new_root.right.clone(),
        });
        RBTree {
            root: Some(blackened),
            len: if was_new { self.len + 1 } else { self.len },
        }
    }

    /// Look up a value by key.
    pub fn get(&self, key: &K) -> Option<&V> {
        get_rec(&self.root, key)
    }

    /// Remove a key, returning a new tree.
    ///
    /// If the key does not exist the returned tree is structurally identical
    /// to `self` (no wasted allocation).
    pub fn remove(&self, key: &K) -> Self {
        let (new_root, found) = delete_rec(&self.root, key);
        if !found {
            return self.clone();
        }
        // Blacken the root.
        let blackened = new_root.map(|r| {
            Rc::new(Node {
                color: Color::Black,
                key: r.key.clone(),
                value: r.value.clone(),
                left: r.left.clone(),
                right: r.right.clone(),
            })
        });
        RBTree {
            root: blackened,
            len: self.len.saturating_sub(1),
        }
    }

    /// Inclusive range scan: returns all `(key, value)` pairs where
    /// `from <= key <= to`, in sorted order.
    pub fn range<'a>(&'a self, from: &K, to: &K) -> Vec<(&'a K, &'a V)> {
        let mut result = Vec::new();
        range_rec(&self.root, from, to, &mut result);
        result
    }

    /// Number of entries in the tree.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Is the tree empty?
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Minimum key-value pair.
    pub fn min(&self) -> Option<(&K, &V)> {
        min_ref(&self.root)
    }

    /// Maximum key-value pair.
    pub fn max(&self) -> Option<(&K, &V)> {
        max_ref(&self.root)
    }

    /// In-order iterator over `(&K, &V)` pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        let mut entries = Vec::new();
        collect_refs(&self.root, &mut entries);
        entries.into_iter()
    }

    /// Check that the cached `len` matches the actual node count.
    /// Used in tests to verify internal consistency.
    #[cfg(test)]
    fn verify_len(&self) -> bool {
        count_nodes(&self.root) == self.len
    }
}

impl<K: Ord + Clone, V: Clone> Default for RBTree<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty() {
        let tree: RBTree<i32, String> = RBTree::new();
        assert!(tree.is_empty());
        assert_eq!(tree.len(), 0);
        assert!(tree.get(&1).is_none());
        assert!(tree.min().is_none());
        assert!(tree.max().is_none());
        assert_eq!(tree.iter().count(), 0);
        assert!(tree.verify_len());
    }

    #[test]
    fn test_insert_get() {
        let tree = RBTree::new()
            .insert(3, "c")
            .insert(1, "a")
            .insert(2, "b");

        assert_eq!(tree.len(), 3);
        assert!(!tree.is_empty());
        assert_eq!(tree.get(&1), Some(&"a"));
        assert_eq!(tree.get(&2), Some(&"b"));
        assert_eq!(tree.get(&3), Some(&"c"));
        assert_eq!(tree.get(&4), None);
        assert!(tree.verify_len());
    }

    #[test]
    fn test_insert_overwrite() {
        let tree = RBTree::new().insert(1, "old").insert(1, "new");
        assert_eq!(tree.len(), 1);
        assert_eq!(tree.get(&1), Some(&"new"));
        assert!(tree.verify_len());
    }

    #[test]
    fn test_insert_many() {
        let mut tree = RBTree::new();
        for i in 0..100 {
            tree = tree.insert(i, i * 10);
        }
        assert_eq!(tree.len(), 100);

        // Every key is retrievable.
        for i in 0..100 {
            assert_eq!(tree.get(&i), Some(&(i * 10)));
        }

        // Sorted order.
        let keys: Vec<i32> = tree.iter().map(|(k, _)| *k).collect();
        for w in keys.windows(2) {
            assert!(w[0] < w[1], "keys must be strictly ascending");
        }

        assert!(tree.verify_len());
    }

    #[test]
    fn test_remove() {
        let tree = RBTree::new()
            .insert(5, "e")
            .insert(3, "c")
            .insert(7, "g")
            .insert(1, "a")
            .insert(9, "i");

        let after = tree.remove(&3);
        assert_eq!(after.len(), 4);
        assert!(after.get(&3).is_none());
        assert_eq!(after.get(&5), Some(&"e"));
        assert_eq!(after.get(&1), Some(&"a"));
        assert_eq!(after.get(&7), Some(&"g"));
        assert_eq!(after.get(&9), Some(&"i"));
        assert!(after.verify_len());

        // Removing a non-existent key returns an equivalent tree.
        let same = after.remove(&42);
        assert_eq!(same.len(), 4);
        assert!(same.verify_len());
    }

    #[test]
    fn test_remove_all() {
        let mut tree = RBTree::new();
        for i in 0..20 {
            tree = tree.insert(i, i);
        }
        for i in 0..20 {
            tree = tree.remove(&i);
            assert!(tree.get(&i).is_none());
            assert!(tree.verify_len());
        }
        assert!(tree.is_empty());
        assert_eq!(tree.len(), 0);
    }

    #[test]
    fn test_range_scan() {
        let tree = RBTree::new()
            .insert(1, "a")
            .insert(3, "c")
            .insert(5, "e")
            .insert(7, "g")
            .insert(9, "i");

        let range = tree.range(&3, &7);
        let keys: Vec<i32> = range.iter().map(|(k, _)| **k).collect();
        assert_eq!(keys, vec![3, 5, 7]);

        // Empty range.
        let empty = tree.range(&10, &20);
        assert!(empty.is_empty());

        // Single element range.
        let single = tree.range(&5, &5);
        assert_eq!(single.len(), 1);
        assert_eq!(*single[0].0, 5);
    }

    #[test]
    fn test_persistence() {
        let v1 = RBTree::new().insert(1, "a").insert(2, "b");
        let v2 = v1.insert(3, "c");
        let v3 = v2.remove(&1);

        // v1 is unchanged.
        assert_eq!(v1.len(), 2);
        assert_eq!(v1.get(&1), Some(&"a"));
        assert_eq!(v1.get(&2), Some(&"b"));
        assert!(v1.get(&3).is_none());

        // v2 has the insertion.
        assert_eq!(v2.len(), 3);
        assert_eq!(v2.get(&3), Some(&"c"));
        assert_eq!(v2.get(&1), Some(&"a"));

        // v3 has the deletion but still has key 2 and 3.
        assert_eq!(v3.len(), 2);
        assert!(v3.get(&1).is_none());
        assert_eq!(v3.get(&2), Some(&"b"));
        assert_eq!(v3.get(&3), Some(&"c"));
    }

    #[test]
    fn test_min_max() {
        let tree = RBTree::new()
            .insert(5, "e")
            .insert(1, "a")
            .insert(9, "i")
            .insert(3, "c");

        assert_eq!(tree.min(), Some((&1, &"a")));
        assert_eq!(tree.max(), Some((&9, &"i")));

        // After removing min and max.
        let t2 = tree.remove(&1).remove(&9);
        assert_eq!(t2.min(), Some((&3, &"c")));
        assert_eq!(t2.max(), Some((&5, &"e")));
    }

    #[test]
    fn test_iter_ordered() {
        let tree = RBTree::new()
            .insert(50, "fifty")
            .insert(30, "thirty")
            .insert(10, "ten")
            .insert(40, "forty")
            .insert(20, "twenty");

        let keys: Vec<i32> = tree.iter().map(|(k, _)| *k).collect();
        assert_eq!(keys, vec![10, 20, 30, 40, 50]);

        let values: Vec<&&str> = tree.iter().map(|(_, v)| v).collect();
        assert_eq!(values, vec![&"ten", &"twenty", &"thirty", &"forty", &"fifty"]);
    }

    #[test]
    fn test_structural_sharing() {
        // Build an initial tree.
        let original = RBTree::new()
            .insert(1, "a")
            .insert(2, "b")
            .insert(3, "c")
            .insert(4, "d")
            .insert(5, "e");

        // Clone and modify one key.
        let modified = original.insert(3, "C");

        // The original is unmodified.
        assert_eq!(original.get(&3), Some(&"c"));
        assert_eq!(modified.get(&3), Some(&"C"));

        // Both trees still have the same unmodified keys, demonstrating that
        // structural sharing works (the Rc pointers to unchanged subtrees are
        // shared). We verify by checking that all non-modified lookups agree.
        for k in &[1, 2, 4, 5] {
            assert_eq!(original.get(k), modified.get(k));
        }

        // Verify Rc-level sharing: the nodes for keys not on the modified
        // path should literally be the same allocation. We check this by
        // confirming the trees have the correct structure and that `Rc`
        // reference counts are > 1 for shared subtrees.
        //
        // We can't directly inspect Rc counts in the public API, but we
        // confirm semantic equivalence: modifying key 3 should not have
        // copied keys 1 or 5's subtree (they are off the modified path).
        assert_eq!(original.len(), 5);
        assert_eq!(modified.len(), 5);

        // Verify via actual Rc::strong_count on a simple case.
        let t1 = RBTree::new().insert(10, "x").insert(20, "y");
        let t2 = t1.insert(20, "Y"); // only modifies right side

        // Both trees are valid.
        assert_eq!(t1.get(&10), Some(&"x"));
        assert_eq!(t1.get(&20), Some(&"y"));
        assert_eq!(t2.get(&10), Some(&"x"));
        assert_eq!(t2.get(&20), Some(&"Y"));

        // The Rc for the left subtree node containing key 10 should be
        // shared (strong_count > 1). We access this through the root.
        if let Some(ref root1) = t1.root {
            if let Some(ref left1) = root1.left {
                // After t2 = t1.insert(20, "Y"), the left child of t2's
                // root should be the same Rc as t1's left child.
                let count = Rc::strong_count(left1);
                assert!(
                    count > 1,
                    "Left subtree Rc should be shared (count={count}), proving structural sharing"
                );
            }
        }
    }

    #[test]
    fn test_insert_reverse_order() {
        // Insert in descending order to exercise different rebalancing paths.
        let mut tree = RBTree::new();
        for i in (0..50).rev() {
            tree = tree.insert(i, i);
        }
        assert_eq!(tree.len(), 50);
        for i in 0..50 {
            assert_eq!(tree.get(&i), Some(&i));
        }
        let keys: Vec<i32> = tree.iter().map(|(k, _)| *k).collect();
        for w in keys.windows(2) {
            assert!(w[0] < w[1]);
        }
        assert!(tree.verify_len());
    }

    #[test]
    fn test_default() {
        let tree: RBTree<String, i32> = RBTree::default();
        assert!(tree.is_empty());
    }
}
