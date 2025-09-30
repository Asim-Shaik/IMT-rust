use serde::{Deserialize, Serialize};

use crate::errors::{IndexerError, IndexerResult};
use crate::tree::{Commitment, MerkleProof};
use crate::utils::{hash_bytes, hash_pair, Hash};

/// Default depth for the Merkle tree
pub const DEFAULT_TREE_DEPTH: usize = 20;

/// Serializable tree that stores only the leaves at each level
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SerializableTree {
    /// Leaves at each level: level_leaves[0] = bottom leaves, level_leaves[depth-1] = root level
    pub level_leaves: Vec<Vec<Hash>>,
    /// Number of leaves at the bottom level
    pub leaf_count: usize,
}

impl SerializableTree {
    /// Create a new serializable tree with the given depth
    pub fn new(depth: usize) -> Self {
        Self {
            level_leaves: vec![Vec::new(); depth],
            leaf_count: 0,
        }
    }

    /// Get the depth of the tree
    pub fn depth(&self) -> usize {
        self.level_leaves.len()
    }

    /// Get the number of leaves at the bottom level
    pub fn len(&self) -> usize {
        self.leaf_count
    }

    /// Check if the tree is empty
    pub fn is_empty(&self) -> bool {
        self.leaf_count == 0
    }
}

/// Full incremental Merkle tree implementation
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IncrementalMerkleTree {
    /// The serializable part of the tree
    pub serializable: SerializableTree,
    /// Tree depth (configurable)
    depth: usize,
    /// Maximum capacity (2^depth)
    capacity: usize,
    /// Precomputed zero hashes for each level
    zero_hashes: Vec<Hash>,
}

impl IncrementalMerkleTree {
    /// Create a new incremental Merkle tree with default depth
    pub fn new() -> Self {
        Self::with_depth(DEFAULT_TREE_DEPTH)
    }

    /// Create a new incremental Merkle tree with specified depth
    pub fn with_depth(depth: usize) -> Self {
        assert!(depth > 0, "depth must be >= 1");
        assert!(depth <= 63, "depth too large");

        let capacity = 1usize << depth;
        let zero_hashes = Self::compute_zero_hashes(depth);

        Self {
            serializable: SerializableTree::new(depth),
            depth,
            capacity,
            zero_hashes,
        }
    }

    /// Create a tree from an existing serializable tree
    pub fn from_serializable(serializable: SerializableTree) -> Self {
        let depth = serializable.depth();
        let capacity = 1usize << depth;
        let zero_hashes = Self::compute_zero_hashes(depth);

        Self {
            serializable,
            depth,
            capacity,
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
        self.serializable.len()
    }

    /// Check if the tree is empty
    pub fn is_empty(&self) -> bool {
        self.serializable.is_empty()
    }

    /// Check if the tree is at full capacity
    pub fn is_full(&self) -> bool {
        self.serializable.len() >= self.capacity
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
        if index < self.serializable.leaf_count {
            self.serializable.level_leaves[0].get(index).copied()
        } else {
            None
        }
    }

    /// Get the hash of a node at a specific level and index
    fn get_node_hash(&self, level: usize, index: usize) -> Hash {
        if level < self.serializable.level_leaves.len() {
            if let Some(&hash) = self.serializable.level_leaves[level].get(index) {
                return hash;
            }
        }

        // Return zero hash if node doesn't exist
        self.zero_hashes[level]
    }

    /// Set a leaf hash directly (for internal use during loading)
    pub fn set_leaf_hash(&mut self, index: usize, hash: Hash) -> IndexerResult<()> {
        if index >= self.capacity {
            return Err(IndexerError::IndexOutOfBounds);
        }

        // Ensure we have enough space in level 0
        while self.serializable.level_leaves[0].len() <= index {
            self.serializable.level_leaves[0].push(self.zero_hashes[0]);
        }

        self.serializable.level_leaves[0][index] = hash;

        // Update leaf count if necessary
        if index >= self.serializable.leaf_count {
            self.serializable.leaf_count = index + 1;
        }

        // Update all levels above
        self.update_levels_after_append(index, hash);

        Ok(())
    }

    /// Set the leaf count directly (for internal use during loading)
    pub fn set_next_index(&mut self, leaf_count: usize) -> IndexerResult<()> {
        if leaf_count > self.capacity {
            return Err(IndexerError::IndexOutOfBounds);
        }
        self.serializable.leaf_count = leaf_count;
        Ok(())
    }

    /// Append a leaf to the tree
    pub fn append(&mut self, leaf_data: &[u8]) -> IndexerResult<usize> {
        if self.is_full() {
            return Err(IndexerError::TreeFull);
        }

        let leaf_hash = hash_bytes(leaf_data);
        let index = self.serializable.leaf_count;

        // Add the leaf to level 0
        self.serializable.level_leaves[0].push(leaf_hash);
        self.serializable.leaf_count += 1;

        // Update all levels above by recomputing the affected nodes
        self.update_levels_after_append(index, leaf_hash);

        Ok(index)
    }

    /// Update all levels after appending a new leaf
    fn update_levels_after_append(&mut self, leaf_index: usize, _leaf_hash: Hash) {
        // Just call the general update function
        self.update_all_affected_levels(leaf_index);
    }

    /// Update an existing leaf
    pub fn update(&mut self, index: usize, leaf_data: &[u8]) -> IndexerResult<()> {
        if index >= self.serializable.leaf_count {
            return Err(IndexerError::IndexOutOfBounds);
        }

        let leaf_hash = hash_bytes(leaf_data);
        self.serializable.level_leaves[0][index] = leaf_hash;

        // Update all affected levels above
        self.update_all_affected_levels(index);

        Ok(())
    }

    /// Update all levels affected by a change at the given leaf index
    fn update_all_affected_levels(&mut self, leaf_index: usize) {
        let mut current_index = leaf_index;

        // Update each level from bottom to top
        for level in 1..self.depth {
            let parent_index = current_index / 2;

            // Ensure we have enough space at this level
            while self.serializable.level_leaves[level].len() <= parent_index {
                self.serializable.level_leaves[level].push(self.zero_hashes[level]);
            }

            // Get left and right child hashes
            let left_child_index = parent_index * 2;
            let right_child_index = parent_index * 2 + 1;

            let left_child = self.get_node_hash(level - 1, left_child_index);
            let right_child = self.get_node_hash(level - 1, right_child_index);

            let parent_hash = hash_pair(&left_child, &right_child);
            self.serializable.level_leaves[level][parent_index] = parent_hash;

            current_index = parent_index;
        }
    }

    /// Insert a commitment into the tree
    pub fn insert_commitment(&mut self, commitment: &Commitment) -> IndexerResult<usize> {
        let commitment_data = bincode::serialize(commitment)?;
        self.append(&commitment_data)
    }

    /// Get the current root hash
    pub fn root(&self) -> Hash {
        if self.depth > 0 {
            self.get_node_hash(self.depth - 1, 0)
        } else {
            self.zero_hashes[0]
        }
    }

    /// Generate a Merkle proof for a leaf at the given index
    pub fn prove(&self, leaf_index: usize) -> IndexerResult<MerkleProof> {
        if leaf_index >= self.serializable.leaf_count {
            return Err(IndexerError::LeafNotAppended);
        }

        // Get the leaf hash
        let leaf = self.get_node_hash(0, leaf_index);

        let mut siblings = Vec::with_capacity(self.depth - 1); // depth - 1 because we don't include root level
        let mut idx = leaf_index;

        // Generate siblings for levels 0 to depth-2 (we don't need a sibling for the root level)
        for level in 0..(self.depth - 1) {
            let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            let sibling_hash = self.get_node_hash(level, sibling_idx);
            siblings.push(sibling_hash);
            idx /= 2;
        }

        Ok(MerkleProof::new(leaf_index, leaf, siblings))
    }
}

impl Default for IncrementalMerkleTree {
    fn default() -> Self {
        Self::new()
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
        assert_eq!(tree.capacity(), 1 << DEFAULT_TREE_DEPTH);

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

        let commitment = Commitment::new(1, 0, [1u8; 32], [2u8; 32], [3u8; 32]);

        let idx = tree.insert_commitment(&commitment).unwrap();
        assert_eq!(idx, 0);

        let proof = tree.prove(idx).unwrap();
        assert!(proof.verify(&tree.root()));
    }
}
