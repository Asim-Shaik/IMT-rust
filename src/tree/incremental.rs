use serde::{Deserialize, Serialize};

use crate::errors::{IndexerError, IndexerResult};
use crate::tree::{Commitment, MerkleProof};
use crate::utils::{hash_bytes, hash_pair, Hash};

/// Fixed depth for the Merkle tree
pub const TREE_DEPTH: usize = 20;

/// In-memory incremental Merkle tree implementation
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IncrementalMerkleTree {
    depth: usize,
    capacity: usize,
    /// Leaves stored as optional hashes (None = empty slot)
    leaves: Vec<Option<Hash>>,
    next_index: usize,
    /// Precomputed zero hashes for each level
    zero_hashes: Vec<Hash>,
}

impl IncrementalMerkleTree {
    /// Create a new incremental Merkle tree with fixed depth
    pub fn new() -> Self {
        Self::with_depth(TREE_DEPTH)
    }

    /// Create a new incremental Merkle tree with specified depth
    pub fn with_depth(depth: usize) -> Self {
        assert!(depth > 0, "depth must be >= 1");
        assert!(depth <= 63, "depth too large");

        let capacity = 1usize << depth;
        let zero_hashes = Self::compute_zero_hashes(depth);

        Self {
            depth,
            capacity,
            leaves: vec![None; capacity],
            next_index: 0,
            zero_hashes,
        }
    }

    /// Compute zero hashes for all levels
    fn compute_zero_hashes(depth: usize) -> Vec<Hash> {
        let mut zero_hashes = Vec::with_capacity(depth + 1);

        // Level 0: hash of single zero byte
        let base_zero = hash_bytes(&[0u8]);
        zero_hashes.push(base_zero);

        // Higher levels: zero_{i+1} = hash_pair(zero_i, zero_i)
        for i in 0..depth {
            let next = hash_pair(&zero_hashes[i], &zero_hashes[i]);
            zero_hashes.push(next);
        }

        zero_hashes
    }

    /// Get the tree's capacity (maximum number of leaves)
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Get the current number of leaves in the tree
    pub fn len(&self) -> usize {
        self.next_index
    }

    /// Check if the tree is empty
    pub fn is_empty(&self) -> bool {
        self.next_index == 0
    }

    /// Check if the tree is at full capacity
    pub fn is_full(&self) -> bool {
        self.next_index >= self.capacity
    }

    /// Get the tree depth
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// Get zero hash for a specific level
    pub fn zero_hash(&self, level: usize) -> Option<Hash> {
        self.zero_hashes.get(level).copied()
    }

    /// Get the hash of a leaf at a specific index (for internal use)
    pub fn get_leaf_hash(&self, index: usize) -> Option<Hash> {
        if index < self.next_index {
            self.leaves[index]
        } else {
            None
        }
    }

    /// Set a leaf hash directly (for internal use during loading)
    pub fn set_leaf_hash(&mut self, index: usize, hash: Hash) -> IndexerResult<()> {
        if index >= self.capacity {
            return Err(IndexerError::IndexOutOfBounds);
        }
        
        self.leaves[index] = Some(hash);
        
        // Update next_index if necessary
        if index >= self.next_index {
            self.next_index = index + 1;
        }
        
        Ok(())
    }

    /// Set the next index directly (for internal use during loading)
    pub fn set_next_index(&mut self, next_index: usize) -> IndexerResult<()> {
        if next_index > self.capacity {
            return Err(IndexerError::IndexOutOfBounds);
        }
        self.next_index = next_index;
        Ok(())
    }

    /// Append a leaf to the tree
    pub fn append(&mut self, leaf_data: &[u8]) -> IndexerResult<usize> {
        if self.is_full() {
            return Err(IndexerError::TreeFull);
        }

        let leaf_hash = hash_bytes(leaf_data);
        let idx = self.next_index;
        self.leaves[idx] = Some(leaf_hash);
        self.next_index += 1;
        Ok(idx)
    }

    /// Update an existing leaf
    pub fn update(&mut self, index: usize, leaf_data: &[u8]) -> IndexerResult<()> {
        if index >= self.next_index {
            return Err(IndexerError::IndexOutOfBounds);
        }

        let leaf_hash = hash_bytes(leaf_data);
        self.leaves[index] = Some(leaf_hash);
        Ok(())
    }

    /// Insert a commitment into the tree
    pub fn insert_commitment(&mut self, commitment: &Commitment) -> IndexerResult<usize> {
        let commitment_data = bincode::serialize(commitment)?;
        self.append(&commitment_data)
    }

    /// Compute the hash of a node at a given level and index
    fn node_hash_at(&self, level: usize, index: usize) -> Hash {
        if level == 0 {
            // Leaf level
            if index < self.capacity {
                if let Some(hash) = self.leaves[index] {
                    return hash;
                }
            }
            // Empty leaf uses zero hash
            return self.zero_hashes[0];
        }

        // Internal node: compute from children
        let left = self.node_hash_at(level - 1, index * 2);
        let right = self.node_hash_at(level - 1, index * 2 + 1);
        hash_pair(&left, &right)
    }

    /// Get the current root hash
    pub fn root(&self) -> Hash {
        self.node_hash_at(self.depth, 0)
    }

    /// Generate a Merkle proof for a leaf at the given index
    pub fn prove(&self, leaf_index: usize) -> IndexerResult<MerkleProof> {
        if leaf_index >= self.next_index {
            return Err(IndexerError::LeafNotAppended);
        }

        // Get the leaf hash
        let leaf = self.leaves[leaf_index]
            .unwrap_or(self.zero_hashes[0]);

        let mut siblings = Vec::with_capacity(self.depth);
        let mut idx = leaf_index;

        for level in 0..self.depth {
            let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            
            let sibling_hash = if level == 0 {
                // Leaf level sibling
                if sibling_idx < self.capacity {
                    self.leaves[sibling_idx].unwrap_or(self.zero_hashes[0])
                } else {
                    self.zero_hashes[0]
                }
            } else {
                // Internal node sibling
                let max_idx_at_level = (1usize << (self.depth - level)) - 1;
                if sibling_idx <= max_idx_at_level {
                    self.node_hash_at(level, sibling_idx)
                } else {
                    self.zero_hashes[level]
                }
            };

            siblings.push(sibling_hash);
            idx /= 2;
        }

        Ok(MerkleProof::new(leaf_index, leaf, siblings))
    }

    /// Create a delta showing the differences between this tree and another
    pub fn create_delta(&self, other: &IncrementalMerkleTree) -> TreeDelta {
        let mut new_leaves = Vec::new();
        let mut updated_leaves = Vec::new();

        // Find new leaves (beyond our current next_index)
        for i in self.next_index..other.next_index {
            if let Some(hash) = other.leaves[i] {
                new_leaves.push((i, hash));
            }
        }

        // Find updated leaves (within our current range)
        for i in 0..self.next_index.min(other.next_index) {
            if self.leaves[i] != other.leaves[i] {
                if let Some(hash) = other.leaves[i] {
                    updated_leaves.push((i, hash));
                }
            }
        }

        TreeDelta {
            base_next_index: self.next_index,
            new_leaves,
            updated_leaves,
        }
    }

    /// Apply a delta to this tree
    pub fn apply_delta(&mut self, delta: &TreeDelta) -> IndexerResult<()> {
        // Apply updated leaves
        for (index, hash) in &delta.updated_leaves {
            if *index >= self.capacity {
                return Err(IndexerError::IndexOutOfBounds);
            }
            self.leaves[*index] = Some(*hash);
        }

        // Apply new leaves
        for (index, hash) in &delta.new_leaves {
            if *index >= self.capacity {
                return Err(IndexerError::IndexOutOfBounds);
            }
            self.leaves[*index] = Some(*hash);
            if *index >= self.next_index {
                self.next_index = *index + 1;
            }
        }

        Ok(())
    }
}

impl Default for IncrementalMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

/// Represents changes between two tree states
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TreeDelta {
    pub base_next_index: usize,
    pub new_leaves: Vec<(usize, Hash)>,
    pub updated_leaves: Vec<(usize, Hash)>,
}

impl TreeDelta {
    /// Check if this delta is empty (no changes)
    pub fn is_empty(&self) -> bool {
        self.new_leaves.is_empty() && self.updated_leaves.is_empty()
    }

    /// Get the total number of changes in this delta
    pub fn change_count(&self) -> usize {
        self.new_leaves.len() + self.updated_leaves.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_operations() {
        let mut tree = IncrementalMerkleTree::new();
        
        assert_eq!(tree.len(), 0);
        assert!(tree.is_empty());
        assert!(!tree.is_full());
        assert_eq!(tree.capacity(), 1 << TREE_DEPTH);

        // Test append
        let idx1 = tree.append(b"test1").unwrap();
        let idx2 = tree.append(b"test2").unwrap();
        
        assert_eq!(idx1, 0);
        assert_eq!(idx2, 1);
        assert_eq!(tree.len(), 2);
        assert!(!tree.is_empty());

        // Test update
        tree.update(0, b"updated_test1").unwrap();
        
        // Test proof generation and verification
        let proof = tree.prove(0).unwrap();
        assert!(proof.verify(&tree.root()));
    }

    #[test]
    fn test_commitment_operations() {
        let mut tree = IncrementalMerkleTree::new();
        
        let commitment = Commitment::new(
            1,
            0,
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
        );

        let idx = tree.insert_commitment(&commitment).unwrap();
        assert_eq!(idx, 0);

        let proof = tree.prove(idx).unwrap();
        assert!(proof.verify(&tree.root()));
    }

    #[test]
    fn test_delta_operations() {
        let mut tree1 = IncrementalMerkleTree::new();
        tree1.append(b"original1").unwrap();
        tree1.append(b"original2").unwrap();

        let mut tree2 = tree1.clone();
        tree2.append(b"new1").unwrap();
        tree2.update(0, b"updated1").unwrap();

        let delta = tree1.create_delta(&tree2);
        assert_eq!(delta.new_leaves.len(), 1);
        assert_eq!(delta.updated_leaves.len(), 1);

        tree1.apply_delta(&delta).unwrap();
        assert_eq!(tree1.root(), tree2.root());
    }
}
