use arcium_indexer::{
    serialization::{SerializationFormat, SerializationOptions},
    Commitment, IncrementalMerkleTree, PersistentMerkleTree, StorageConfig,
};
use tempfile::TempDir;

#[test]
fn test_persistent_tree_basic_operations() {
    let temp_dir = TempDir::new().unwrap();
    let config = StorageConfig::new(temp_dir.path())
        .with_cache_size(64 * 1024)
        .with_wal(true);

    let mut tree = PersistentMerkleTree::new(config).unwrap();

    // Test basic operations
    assert_eq!(tree.len(), 0);
    assert!(tree.is_empty());

    // Append some leaves
    let index1 = tree.append(b"test1").unwrap();
    let index2 = tree.append(b"test2").unwrap();
    let index3 = tree.append(b"test3").unwrap();

    assert_eq!(index1, 0);
    assert_eq!(index2, 1);
    assert_eq!(index3, 2);
    assert_eq!(tree.len(), 3);
    assert!(!tree.is_empty());

    // Test updates
    tree.update(0, b"updated_test1").unwrap();

    // Test proofs
    let proof = tree.prove(1).unwrap();
    let root = tree.root();

    assert!(proof.verify(&root));

    // Sync to disk
    tree.sync().unwrap();
}

#[test]
fn test_persistent_tree_persistence() {
    let temp_dir = TempDir::new().unwrap();
    let config = StorageConfig::new(temp_dir.path())
        .with_cache_size(64 * 1024)
        .with_wal(true);

    let original_root;
    let original_len;

    // Create tree and add data
    {
        let mut tree = PersistentMerkleTree::new(config.clone()).unwrap();
        tree.append(b"persistent1").unwrap();
        tree.append(b"persistent2").unwrap();
        tree.append(b"persistent3").unwrap();

        original_root = tree.root();
        original_len = tree.len();

        tree.sync().unwrap();
    }

    // Reopen tree and verify data persisted
    {
        let tree = PersistentMerkleTree::new(config).unwrap();
        assert_eq!(tree.root(), original_root);
        assert_eq!(tree.len(), original_len);

        // Verify we can still generate proofs after reopening
        let proof = tree.prove(1).unwrap();
        assert!(proof.verify(&original_root));
    }
}

#[test]
fn test_in_memory_tree_operations() {
    let mut tree = IncrementalMerkleTree::new(20);

    // Test basic operations
    assert_eq!(tree.len(), 0);
    assert!(tree.is_empty());
    assert!(!tree.is_full());

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

    let proof2 = tree.prove(1).unwrap();
    assert!(proof2.verify(&tree.root()));
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
fn test_commitment_serialization() {
    let commitment = Commitment::new(1, 42, [1u8; 32], [2u8; 32], [3u8; 32]);

    // Test binary serialization
    let bytes = commitment.to_bytes();
    let parsed = Commitment::from_bytes(&bytes).unwrap();

    assert_eq!(commitment.version, parsed.version);
    assert_eq!(commitment.commitment_index, parsed.commitment_index);
    assert_eq!(commitment.hash, parsed.hash);
    assert_eq!(commitment.random_secret, parsed.random_secret);
    assert_eq!(commitment.nullifier, parsed.nullifier);
}

#[test]
fn test_tree_serialization() {
    let mut tree = IncrementalMerkleTree::new(20);
    tree.append(b"test1").unwrap();
    tree.append(b"test2").unwrap();
    tree.append(b"test3").unwrap();

    let original_root = tree.root();

    // Test basic bincode serialization (which is what the tree uses internally)
    let serialized = bincode::serialize(&tree).unwrap();
    let deserialized: IncrementalMerkleTree = bincode::deserialize(&serialized).unwrap();

    assert_eq!(original_root, deserialized.root());
    assert_eq!(tree.len(), deserialized.len());

    // Test that we can generate proofs from the deserialized tree
    let proof = deserialized.prove(0).unwrap();
    assert!(proof.verify(&original_root));
}

#[test]
fn test_error_handling() {
    let mut tree = IncrementalMerkleTree::new(20);

    // Test updating non-existent leaf
    assert!(tree.update(100, b"nonexistent").is_err());

    // Test proving non-existent leaf
    assert!(tree.prove(100).is_err());

    // Add one leaf and test boundary conditions
    tree.append(b"test").unwrap();
    assert!(tree.update(1, b"out_of_bounds").is_err());
    assert!(tree.prove(1).is_err());

    // Valid operations should still work
    assert!(tree.update(0, b"valid_update").is_ok());
    assert!(tree.prove(0).is_ok());
}

#[test]
fn test_zero_hashes() {
    let tree = IncrementalMerkleTree::new(20);

    // Should have zero hashes for all levels
    for level in 0..=tree.depth() {
        assert!(tree.zero_hash(level).is_some());
    }

    // Beyond max level should return None
    assert!(tree.zero_hash(tree.depth() + 1).is_none());
}
