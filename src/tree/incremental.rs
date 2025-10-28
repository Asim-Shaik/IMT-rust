use serde::{Deserialize, Serialize};

use crate::errors::{IndexerError, IndexerResult};
use crate::tree::{Commitment, MerkleProof};
use crate::utils::{
    internal::{hash_bytes, hash_pair},
    Hash,
};

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

impl Default for SerializableTree {
    fn default() -> Self {
        Self::new()
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
    /// Frontier: rightmost nodes at each level (for O(depth) operations)
    #[serde(skip)]
    frontier: Vec<Hash>,
    // Note: cached_nodes was planned but not used in current implementation
    // Will be added when needed for optimization
}

impl IncrementalMerkleTree {
    /// Create a new incremental Merkle tree with specified depth
    pub fn new(depth: usize) -> Self {
        Self::with_depth(depth)
    }

    /// Create a new incremental Merkle tree with specified depth
    pub fn with_depth(depth: usize) -> Self {
        assert!(depth > 0, "depth must be >= 1");
        assert!(depth <= 63, "depth too large");

        let capacity = 1usize << depth;
        let zero_hashes = Self::compute_zero_hashes(depth);

        let frontier = vec![zero_hashes[0]; depth + 1]; // Initialize frontier with zero hashes

        Self {
            serializable: SerializableTree::new(),
            depth,
            capacity,
            zero_hashes,
            frontier,
        }
    }

    /// Create a tree from an existing serializable tree with specified depth
    pub fn from_serializable(serializable: SerializableTree, depth: usize) -> Self {
        let capacity = 1usize << depth;
        let zero_hashes = Self::compute_zero_hashes(depth);
        let frontier = vec![zero_hashes[0]; depth + 1];

        Self {
            serializable,
            depth,
            capacity,
            zero_hashes,
            frontier,
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

    /// Append a leaf to the tree using true incremental updates
    pub fn append(&mut self, leaf_data: &[u8]) -> IndexerResult<usize> {
        if self.is_full() {
            return Err(IndexerError::TreeFull);
        }

        let leaf_hash = hash_bytes(leaf_data);
        let index = self.serializable.leaves.len();

        // Add the leaf to the bottom level
        self.serializable.leaves.push(leaf_hash);

        // True IMT: Update frontier incrementally - O(depth) operation
        let mut current_hash = leaf_hash;
        let mut pos = index;

        // Bubble up the frontier path
        for level in 0..self.depth {
            if pos % 2 == 0 {
                // Current node is left child, combine with right sibling (zero or frontier)
                let right = if pos + 1 < self.serializable.leaves.len() {
                    self.serializable.leaves[pos + 1]
                } else {
                    self.zero_hashes[level]
                };
                let parent = hash_pair(&current_hash, &right);
                self.frontier[level + 1] = parent;
                current_hash = parent;
            } else {
                // Current node is right child, combine frontier with left
                let left = self.frontier[level];
                let parent = hash_pair(&left, &current_hash);
                self.frontier[level + 1] = parent;
                current_hash = parent;
            }
            pos /= 2;
        }

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

    /// Get the current root hash
    pub fn root(&self) -> Hash {
        if self.serializable.leaves.is_empty() {
            return self.zero_hashes[self.depth];
        }

        // Recompute root deterministically from leaves to match proof logic
        let mut level_nodes = self.serializable.leaves.clone();
        for lvl in 0..self.depth {
            let mut next_level = Vec::with_capacity((level_nodes.len() + 1) / 2);
            for i in (0..level_nodes.len()).step_by(2) {
                let left = level_nodes[i];
                let right = if i + 1 < level_nodes.len() {
                    level_nodes[i + 1]
                } else {
                    self.zero_hashes[lvl]
                };
                next_level.push(hash_pair(&left, &right));
            }
            level_nodes = next_level;
        }

        level_nodes
            .get(0)
            .copied()
            .unwrap_or(self.zero_hashes[self.depth])
    }

    /// Rebuild the frontier from leaves after deserialization
    pub fn rebuild_frontier(&mut self) -> IndexerResult<()> {
        // Rebuild frontier by recomputing rightmost path for each level
        if self.serializable.leaves.is_empty() {
            self.frontier = vec![self.zero_hashes[0]; self.depth + 1];
            return Ok(());
        }

        // Rebuild frontier by simulating insertions for all leaves
        let num_leaves = self.serializable.leaves.len();

        // Reset frontier to zeros
        self.frontier = vec![self.zero_hashes[0]; self.depth + 1];

        // Rebuild frontier by simulating all insertions
        for i in 0..num_leaves {
            let leaf_hash = self.serializable.leaves[i];
            let mut current_hash = leaf_hash;
            let mut pos = i;

            // Bubble up the frontier path
            for level in 0..self.depth {
                if pos % 2 == 0 {
                    // Current node is left child
                    let right = if pos + 1 < num_leaves {
                        self.serializable.leaves[pos + 1]
                    } else {
                        self.zero_hashes[level]
                    };
                    let parent = hash_pair(&current_hash, &right);
                    self.frontier[level + 1] = parent;
                    current_hash = parent;
                } else {
                    // Current node is right child
                    let left = self.frontier[level];
                    let parent = hash_pair(&left, &current_hash);
                    self.frontier[level + 1] = parent;
                    current_hash = parent;
                }
                pos /= 2;
            }
        }

        Ok(())
    }

    /// Generate a Merkle proof for a leaf at the given index
    pub fn prove(&self, leaf_index: usize) -> IndexerResult<MerkleProof> {
        if leaf_index >= self.serializable.leaves.len() {
            return Err(IndexerError::LeafNotAppended);
        }

        // Use the working root() method to compute the correct root
        // Then generate proof using full recomputation (correct but not O(depth))
        let leaf = self.serializable.leaves[leaf_index];
        let mut siblings = Vec::with_capacity(self.depth);
        let mut current_level = self.serializable.leaves.clone();
        let mut idx = leaf_index;

        // Generate siblings by computing each level
        for level in 0..self.depth {
            let sibling_idx = idx ^ 1;

            let sibling_hash = if sibling_idx < current_level.len() {
                current_level[sibling_idx]
            } else {
                self.zero_hashes[level]
            };

            siblings.push(sibling_hash);

            // Compute next level
            let mut next_level = Vec::new();
            for i in (0..current_level.len()).step_by(2) {
                let left = current_level[i];
                let right = if i + 1 < current_level.len() {
                    current_level[i + 1]
                } else {
                    self.zero_hashes[level]
                };
                next_level.push(hash_pair(&left, &right));
            }

            current_level = next_level;
            idx /= 2;
        }

        Ok(MerkleProof::new(leaf_index, leaf, siblings))
    }
}

impl Default for IncrementalMerkleTree {
    fn default() -> Self {
        Self::new(crate::tree::DEFAULT_TREE_DEPTH)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_operations() {
        let mut tree = IncrementalMerkleTree::new(crate::tree::DEFAULT_TREE_DEPTH);

        assert_eq!(tree.len(), 0);
        assert!(tree.is_empty());
        assert!(!tree.is_full());
        assert_eq!(tree.capacity(), 1 << crate::tree::DEFAULT_TREE_DEPTH);

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
        let mut tree = IncrementalMerkleTree::new(crate::tree::DEFAULT_TREE_DEPTH);

        let commitment = Commitment::new(1, 0, [1u8; 32], [2u8; 32], [3u8; 32]);

        let idx = tree.insert_commitment(&commitment).unwrap();
        assert_eq!(idx, 0);

        let proof = tree.prove(idx).unwrap();
        assert!(proof.verify(&tree.root()));
    }
}
