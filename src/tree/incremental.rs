use serde::{Deserialize, Serialize};

use crate::errors::{IndexerError, IndexerResult};
use crate::tree::{Commitment, MerkleProof};
use crate::utils::{hash_bytes, hash_pair, Hash};

/// Default depth for the Merkle tree
pub const DEFAULT_TREE_DEPTH: usize = 20;

/// Serializable tree that stores only the bottom-most leaf nodes
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SerializableTree {
    /// Only the leaf nodes at the bottom level (no predefined capacity)
    pub leaves: Vec<Hash>,
}

impl SerializableTree {
    /// Create a new serializable tree (no predefined capacity)
    pub fn new() -> Self {
        Self { leaves: Vec::new() }
    }

    /// Get the number of leaves
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Check if the tree is empty
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
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
            serializable: SerializableTree::new(),
            depth,
            capacity,
            zero_hashes,
        }
    }

    /// Create a tree from an existing serializable tree (assumes DEFAULT_TREE_DEPTH)
    pub fn from_serializable(serializable: SerializableTree) -> Self {
        let depth = DEFAULT_TREE_DEPTH;
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
        self.serializable.leaves.get(index).copied()
    }

    /// Set a leaf hash directly (for internal use during loading)
    pub fn set_leaf_hash(&mut self, index: usize, hash: Hash) -> IndexerResult<()> {
        if index >= self.capacity {
            return Err(IndexerError::IndexOutOfBounds);
        }

        // Ensure we have enough space in the leaves vector
        while self.serializable.leaves.len() <= index {
            self.serializable.leaves.push(self.zero_hashes[0]);
        }

        self.serializable.leaves[index] = hash;
        Ok(())
    }

    /// Set the leaf count directly (for internal use during loading) - now a no-op since we use Vec::len()
    pub fn set_next_index(&mut self, leaf_count: usize) -> IndexerResult<()> {
        // Ensure the leaves vector has the right size
        self.serializable
            .leaves
            .resize(leaf_count, self.zero_hashes[0]);
        Ok(())
    }

    /// Append a leaf to the tree
    pub fn append(&mut self, leaf_data: &[u8]) -> IndexerResult<usize> {
        if self.is_full() {
            return Err(IndexerError::TreeFull);
        }

        let leaf_hash = hash_bytes(leaf_data);
        let index = self.serializable.leaves.len();

        // Add the leaf to the bottom level (no predefined capacity)
        self.serializable.leaves.push(leaf_hash);

        Ok(index)
    }

    /// Update an existing leaf
    pub fn update(&mut self, index: usize, leaf_data: &[u8]) -> IndexerResult<()> {
        if index >= self.serializable.leaves.len() {
            return Err(IndexerError::IndexOutOfBounds);
        }

        let leaf_hash = hash_bytes(leaf_data);
        self.serializable.leaves[index] = leaf_hash;

        Ok(())
    }

    /// Insert a commitment into the tree
    pub fn insert_commitment(&mut self, commitment: &Commitment) -> IndexerResult<usize> {
        let commitment_data = bincode::serialize(commitment)?;
        self.append(&commitment_data)
    }

    /// Get the current root hash (computed using incremental tree properties)
    pub fn root(&self) -> Hash {
        if self.serializable.leaves.is_empty() {
            return self.zero_hashes[self.depth - 1];
        }

        // Compute root by building the tree level by level using incremental properties
        let mut current_level = self.serializable.leaves.clone();
        let mut level = 0;

        while current_level.len() > 1 || level < self.depth - 1 {
            let mut next_level = Vec::new();
            let mut i = 0;

            while i < current_level.len() || next_level.is_empty() {
                let left = if i < current_level.len() {
                    current_level[i]
                } else {
                    self.zero_hashes[level]
                };

                let right = if i + 1 < current_level.len() {
                    current_level[i + 1]
                } else {
                    self.zero_hashes[level]
                };

                next_level.push(hash_pair(&left, &right));
                i += 2;
            }

            current_level = next_level;
            level += 1;

            if level >= self.depth - 1 {
                break;
            }
        }

        current_level[0]
    }

    /// Generate a Merkle proof for a leaf at the given index using incremental tree properties
    pub fn prove(&self, leaf_index: usize) -> IndexerResult<MerkleProof> {
        if leaf_index >= self.serializable.leaves.len() {
            return Err(IndexerError::LeafNotAppended);
        }

        // Get the leaf hash
        let leaf = self.serializable.leaves[leaf_index];

        let mut siblings = Vec::with_capacity(self.depth - 1);
        let mut current_level = self.serializable.leaves.clone();
        let mut idx = leaf_index;
        let mut level = 0;

        // Generate siblings by computing each level using incremental properties
        while level < self.depth - 1 {
            // Find sibling at current level
            let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };

            let sibling_hash = if sibling_idx < current_level.len() {
                current_level[sibling_idx]
            } else {
                self.zero_hashes[level]
            };

            siblings.push(sibling_hash);

            // Compute next level
            let mut next_level = Vec::new();
            let mut i = 0;
            while i < current_level.len() {
                let left = current_level[i];
                let right = if i + 1 < current_level.len() {
                    current_level[i + 1]
                } else {
                    self.zero_hashes[level]
                };
                next_level.push(hash_pair(&left, &right));
                i += 2;
            }

            current_level = next_level;
            idx /= 2;
            level += 1;
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
