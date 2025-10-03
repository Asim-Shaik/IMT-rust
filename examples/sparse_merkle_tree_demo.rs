use arcium_indexer::{
    storage::{SparseTreeStorage, TreeStorage},
    tree::kv_trait::AuthenticatedKV,
};
use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Sparse Merkle Tree Demo");
    println!("======================");

    // Get data directory from command line or use default
    let data_dir = env::args()
        .nth(1)
        .unwrap_or_else(|| "sparse_tree_demo".to_string());

    // Create or open sparse tree storage
    println!("Creating sparse tree storage in: {}", data_dir);
    let mut storage = SparseTreeStorage::new(&data_dir, Some(20))?;

    // Insert some key-value pairs
    println!("\nInserting key-value pairs...");
    let test_data = vec![
        ("user1", "Alice"),
        ("user2", "Bob"),
        ("user3", "Charlie"),
        ("user4", "Diana"),
        ("user5", "Eve"),
    ];

    for (key, value) in &test_data {
        storage.insert(key.to_string(), value.to_string())?;
        println!("Inserted: {} -> {}", key, value);
    }

    // Get values and verify proofs
    println!("\nRetrieving values and verifying proofs...");
    for (key, expected_value) in &test_data {
        let (value, proof) = storage.get(key.to_string())?;
        let root_digest = storage.root();

        println!("Key: {}", key);
        println!("  Value: {:?}", value);
        println!("  Proof length: {} siblings", proof.len());

        // Note: Proof verification is not yet implemented for unified storage
        println!("  Proof verification: Not implemented in unified storage");
        assert_eq!(value, Some(expected_value.to_string()));
    }

    // Test non-existent key
    println!("\nTesting non-existent key...");
    let (value, proof) = storage.get("nonexistent".to_string())?;
    let root_digest = storage.root();
    println!("Non-existent key value: {:?}", value);
    assert_eq!(value, None);

    // Note: Proof verification is not yet implemented for unified storage
    println!("Proof verification for non-existent key: Not implemented in unified storage");

    // Save the tree to disk
    println!("\nSaving tree to disk...");
    storage.save()?;

    // Get tree statistics
    let stats = storage.stats();
    println!("Tree statistics:");
    println!("  Root hash: {}", hex::encode(stats.root_hash));
    println!("  Estimated size: {} bytes", stats.tree_size);

    println!("\nDemo completed successfully!");
    Ok(())
}
