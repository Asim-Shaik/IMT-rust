use umbra_indexer::{
    errors::IndexerResult,
    storage::{create_tree_storage, TreeStorage, TreeType},
    tree::Commitment,
};

fn main() -> IndexerResult<()> {
    println!("=== Unified Tree Storage Demo ===");

    // Create demo directory in current working directory
    let temp_dir = std::env::current_dir()?.join("unified_demo_output");
    std::fs::create_dir_all(&temp_dir)?;
    println!("Files will be saved to: {}", temp_dir.display());

    // Demo 1: Incremental Tree Storage
    println!("\n1. Testing Incremental Tree Storage:");
    let mut incremental_storage = create_tree_storage(TreeType::Incremental, &temp_dir, Some(20))?;

    // Create some test commitments
    let commitment1 = Commitment::new(1, 0, [1u8; 32], [2u8; 32], [3u8; 32]);
    let commitment2 = Commitment::new(1, 1, [4u8; 32], [5u8; 32], [6u8; 32]);

    // Insert commitments
    incremental_storage.insert_commitment(&commitment1)?;
    incremental_storage.insert_commitment(&commitment2)?;

    println!("   - Inserted 2 commitments");
    println!("   - Tree length: {}", incremental_storage.len());
    println!(
        "   - Root hash: {}",
        hex::encode(incremental_storage.root())
    );

    // Save to disk
    incremental_storage.save()?;
    println!("   - Saved to disk");

    // Demo 2: Sparse Tree Storage
    println!("\n2. Testing Sparse Tree Storage:");
    let mut sparse_storage = create_tree_storage(TreeType::Sparse, &temp_dir, Some(20))?;

    // Insert the same commitments
    sparse_storage.insert_commitment(&commitment1)?;
    sparse_storage.insert_commitment(&commitment2)?;

    println!("   - Inserted 2 commitments");
    println!("   - Tree length: {}", sparse_storage.len());
    println!("   - Root hash: {}", hex::encode(sparse_storage.root()));

    // Retrieve commitment from sparse tree
    let retrieved_commitment = sparse_storage.get_commitment(0)?;
    if let Some(comm) = retrieved_commitment {
        println!(
            "   - Retrieved commitment 0: version={}, index={}",
            comm.version, comm.commitment_index
        );
    }

    // Save to disk
    sparse_storage.save()?;
    println!("   - Saved to disk");

    // Demo 3: Plug-and-play usage
    println!("\n3. Testing Plug-and-Play Usage:");

    // Function that works with any tree storage
    fn process_tree_storage(storage: &mut dyn TreeStorage, tree_name: &str) -> IndexerResult<()> {
        let commitment = Commitment::new(1, 42, [7u8; 32], [8u8; 32], [9u8; 32]);
        storage.insert_commitment(&commitment)?;

        let stats = storage.stats();
        println!(
            "   - {}: length={}, type={:?}, root={}",
            tree_name,
            stats.tree_size,
            stats.tree_type,
            hex::encode(stats.root_hash)
        );

        storage.save()?;
        Ok(())
    }

    // Use the same function with both tree types
    let mut incremental_storage2 = create_tree_storage(TreeType::Incremental, &temp_dir, Some(20))?;
    let mut sparse_storage2 = create_tree_storage(TreeType::Sparse, &temp_dir, Some(20))?;

    process_tree_storage(&mut *incremental_storage2, "Incremental")?;
    process_tree_storage(&mut *sparse_storage2, "Sparse")?;

    // Demo 4: Statistics comparison
    println!("\n4. Tree Statistics Comparison:");
    let incremental_stats = incremental_storage.stats();
    let sparse_stats = sparse_storage.stats();

    println!("   Incremental Tree:");
    println!("     - Type: {:?}", incremental_stats.tree_type);
    println!("     - Size: {}", incremental_stats.tree_size);
    println!("     - Root: {}", hex::encode(incremental_stats.root_hash));

    println!("   Sparse Tree:");
    println!("     - Type: {:?}", sparse_stats.tree_type);
    println!("     - Size: {}", sparse_stats.tree_size);
    println!("     - Root: {}", hex::encode(sparse_stats.root_hash));

    println!("\n=== Demo Complete ===");
    Ok(())
}
