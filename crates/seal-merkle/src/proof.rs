//! Merkle inclusion/exclusion proofs.
//!
//! A proof that a key exists (or doesn't exist) in the tree,
//! verifiable against the root hash without the full tree.

use crate::node::{Node, NodeRef};
use crate::store::NodeStore;
use seal_crypto::hash::Hash256;
use serde::{Deserialize, Serialize};

/// A step in a Merkle proof path.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofStep {
    /// The node at this level.
    pub node: Node,
    /// Which child index was followed to reach the next level.
    pub child_index: usize,
}

/// A Merkle proof for a key lookup.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Path from root to the leaf/termination point.
    pub path: Vec<ProofStep>,
    /// The key being proven.
    pub key: Vec<u8>,
    /// The value, if the key exists (inclusion proof).
    pub value: Option<Vec<u8>>,
}

impl MerkleProof {
    /// Verify this proof against a root hash.
    pub fn verify(&self, root_hash: &Hash256) -> bool {
        if self.path.is_empty() {
            return false;
        }

        // Verify the chain of hashes from root down
        let first_node_hash = self.path[0].node.content_hash();
        if first_node_hash != *root_hash {
            return false;
        }

        // Each step's child hash must match the next step's node hash
        for i in 0..self.path.len() - 1 {
            let step = &self.path[i];
            let next_step = &self.path[i + 1];
            let next_hash = next_step.node.content_hash();

            let child_ref = &step.node.children[step.child_index];
            match child_ref {
                NodeRef::Hash(h) if *h == next_hash => {}
                _ => return false,
            }
        }

        // Verify the key is (or isn't) in the final node
        let last_node = &self.path.last().unwrap().node;
        match last_node.find_key_pos(&self.key) {
            Ok(idx) => {
                // Key found — inclusion proof
                self.value.as_ref() == Some(&last_node.entries[idx].value)
            }
            Err(_) => {
                // Key not found — exclusion proof
                self.value.is_none()
            }
        }
    }
}

/// Generate a Merkle proof for a key.
pub fn generate_proof<S: NodeStore>(store: &S, root: &NodeRef, key: &[u8]) -> Option<MerkleProof> {
    let mut path = Vec::new();
    let mut current_hash = *root.hash()?;
    let mut value = None;

    loop {
        let node = store.get(&current_hash)?;

        match node.find_key_pos(key) {
            Ok(idx) => {
                value = Some(node.entries[idx].value.clone());
                path.push(ProofStep {
                    node,
                    child_index: 0,
                });
                break;
            }
            Err(idx) => {
                if node.is_leaf() {
                    path.push(ProofStep {
                        node,
                        child_index: 0,
                    });
                    break;
                }
                let child_hash = *node.children[idx].hash()?;
                path.push(ProofStep {
                    node,
                    child_index: idx,
                });
                current_hash = child_hash;
            }
        }
    }

    Some(MerkleProof {
        path,
        key: key.to_vec(),
        value,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemoryStore;
    use crate::tree::MerkleTree;

    #[test]
    fn test_inclusion_proof() {
        let mut tree = MerkleTree::new(MemoryStore::new());
        tree.insert(b"alice".to_vec(), b"100".to_vec()).unwrap();
        tree.insert(b"bob".to_vec(), b"200".to_vec()).unwrap();

        let root_hash = *tree.root_hash().unwrap();
        let proof = generate_proof(tree.store(), tree.root_ref(), b"alice").unwrap();

        assert_eq!(proof.value, Some(b"100".to_vec()));
        assert!(proof.verify(&root_hash));
    }

    #[test]
    fn test_exclusion_proof() {
        let mut tree = MerkleTree::new(MemoryStore::new());
        tree.insert(b"alice".to_vec(), b"100".to_vec()).unwrap();

        let root_hash = *tree.root_hash().unwrap();
        let proof = generate_proof(tree.store(), tree.root_ref(), b"missing").unwrap();

        assert_eq!(proof.value, None);
        assert!(proof.verify(&root_hash));
    }

    #[test]
    fn test_proof_fails_wrong_root() {
        let mut tree = MerkleTree::new(MemoryStore::new());
        tree.insert(b"alice".to_vec(), b"100".to_vec()).unwrap();

        let proof = generate_proof(tree.store(), tree.root_ref(), b"alice").unwrap();
        let fake_root = Hash256([0xff; 32]);
        assert!(!proof.verify(&fake_root));
    }
}
