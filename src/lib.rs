//! Arcium Indexer - High-performance persistent Merkle tree implementation
//!
//! This crate provides an efficient, file-backed Merkle tree implementation
//! optimized for blockchain indexing applications.

pub mod config;
pub mod errors;
pub mod serialization;
pub mod storage;
pub mod tree;
pub mod utils;

// Re-export commonly used types
pub use config::IndexerConfig;
pub use errors::{IndexerError, IndexerResult};
pub use storage::{PersistentMerkleTree, StorageConfig};
pub use tree::{Commitment, IncrementalMerkleTree, MerkleProof};
pub use utils::Hash;

// Legacy API compatibility functions
use tree::IncrementalMerkleTree as Tree;

/// Parse a new commitment from raw data (legacy API)
pub fn parse_new_commitment(data: &[u8]) -> Result<Commitment, &'static str> {
    match Commitment::from_bytes(data) {
        Ok(commitment) => Ok(commitment),
        Err(_) => Err("failed to parse commitment"),
    }
}

/// Insert a commitment into the incremental Merkle tree (legacy API)
pub fn insert_into_incremental_merkle_tree(
    tree: &mut Tree,
    commitment: &Commitment,
) -> Result<usize, &'static str> {
    match tree.insert_commitment(commitment) {
        Ok(index) => Ok(index),
        Err(_) => Err("failed to insert commitment"),
    }
}

/// Get the Merkle path for a commitment at a specific index (legacy API)
pub fn get_merkle_path_for_commitment(
    tree: &Tree,
    commitment_index: usize,
) -> Result<MerkleProof, &'static str> {
    match tree.prove(commitment_index) {
        Ok(proof) => Ok(proof),
        Err(_) => Err("failed to generate proof"),
    }
}

/// Persist the incremental Merkle tree fully (legacy API)
pub fn persist_incremental_merkle_tree_fully(tree: &Tree) -> Result<Vec<u8>, &'static str> {
    match bincode::serialize(tree) {
        Ok(data) => Ok(data),
        Err(_) => Err("failed to serialize tree"),
    }
}

/// Persist the incremental Merkle tree (lighter version) (legacy API)
pub fn persist_incremental_merkle_tree(tree: &Tree) -> Result<Vec<u8>, &'static str> {
    // For the lighter version, just use the same serialization for now
    persist_incremental_merkle_tree_fully(tree)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_tree_operations() {
        let mut tree = IncrementalMerkleTree::new(20);

        // Test basic operations
        assert_eq!(tree.len(), 0);
        assert!(tree.is_empty());

        // Add some leaves
        let idx1 = tree.append(b"test1").unwrap();
        let idx2 = tree.append(b"test2").unwrap();

        assert_eq!(idx1, 0);
        assert_eq!(idx2, 1);
        assert_eq!(tree.len(), 2);

        // Generate and verify proof
        let proof = tree.prove(0).unwrap();
        assert!(proof.verify(&tree.root()));
    }

    #[test]
    fn test_commitment_operations() {
        let mut tree = IncrementalMerkleTree::new(20);

        let commitment = Commitment::new(1, 42, [1u8; 32], [2u8; 32], [3u8; 32]);

        let index = tree.insert_commitment(&commitment).unwrap();
        assert_eq!(index, 0);

        let proof = tree.prove(index).unwrap();
        assert!(proof.verify(&tree.root()));
    }

    #[test]
    fn test_legacy_api_compatibility() {
        let mut tree = IncrementalMerkleTree::new(20);

        // Test legacy commitment parsing
        let commitment_data = Commitment::new(1, 0, [1u8; 32], [2u8; 32], [3u8; 32]).to_bytes();
        let parsed = parse_new_commitment(&commitment_data).unwrap();

        // Test legacy insertion
        let index = insert_into_incremental_merkle_tree(&mut tree, &parsed).unwrap();
        assert_eq!(index, 0);

        // Test legacy proof generation
        let proof = get_merkle_path_for_commitment(&tree, index).unwrap();
        assert!(proof.verify(&tree.root()));

        // Test legacy serialization
        let serialized = persist_incremental_merkle_tree_fully(&tree).unwrap();
        assert!(!serialized.is_empty());
    }
}
