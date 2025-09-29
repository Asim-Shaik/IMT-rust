use arcium_indexer::*;
use std::time::Instant;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🌳 Arcium Indexer - File-Based Merkle Tree Demo");
    println!("================================================\n");

    // Create storage configuration
    let config = StorageConfig {
        data_dir: std::path::PathBuf::from("./demo_data"),
        cache_size: 512 * 1024, // 512KB cache
        sync_interval: std::time::Duration::from_secs(2),
        compression: true,
        enable_wal: true,
    };

    println!("📁 Storage Config:");
    println!("   Data directory: {:?}", config.data_dir);
    println!("   Cache size: {} KB", config.cache_size / 1024);
    println!("   Compression: {}", config.compression);
    println!("   Write-ahead logging: {}\n", config.enable_wal);

    // Create or open persistent tree
    println!("🔧 Creating/Opening persistent Merkle tree...");
    let start = Instant::now();
    let mut tree = PersistentMerkleTree::new(config)?;
    println!("✅ Tree initialized in {:?}\n", start.elapsed());

    // Show initial state
    println!("📊 Initial tree state:");
    println!("   Length: {} leaves", tree.len());
    println!("   Root: {}", hex::encode(tree.root()));
    println!(
        "   Zero hash (level 0): {}",
        hex::encode(tree.zero_hash(0).unwrap())
    );
    println!(
        "   Zero hash (level 20): {}\n",
        hex::encode(tree.zero_hash(20).unwrap())
    );

    // Add some commitments
    println!("📝 Adding commitments to the tree...");
    let commitments = vec![
        "Alice's commitment to secret value 123",
        "Bob's commitment to secret value 456",
        "Charlie's commitment to secret value 789",
        "Diana's commitment to secret value 101112",
        "Eve's commitment to secret value 131415",
    ];

    let mut indices = Vec::new();
    for (i, commitment) in commitments.iter().enumerate() {
        let start = Instant::now();
        let index = tree.append(commitment.as_bytes())?;
        let duration = start.elapsed();

        indices.push(index);
        println!(
            "   [{}] Added: '{}' (took {:?})",
            index, commitment, duration
        );
    }

    // Show updated state
    println!("\n📊 Updated tree state:");
    println!("   Length: {} leaves", tree.len());
    println!("   Root: {}\n", hex::encode(tree.root()));

    // Demonstrate proof generation
    println!("🔍 Generating Merkle proofs...");
    for &index in &indices[0..3] {
        // Just first 3 for brevity
        let start = Instant::now();
        let proof = tree.prove(index)?;
        let duration = start.elapsed();

        println!(
            "   Proof for leaf {}: {} siblings (generated in {:?})",
            index,
            proof.siblings.len(),
            duration
        );

        // Verify the proof
        let is_valid = IncrementalMerkleTree::verify_proof(
            &proof.leaf,
            proof.leaf_index,
            &proof.siblings,
            &tree.root(),
        );
        println!(
            "     Verification: {}",
            if is_valid { "✅ VALID" } else { "❌ INVALID" }
        );
    }

    // Demonstrate updates
    println!("\n✏️  Updating a commitment...");
    let new_commitment = "Alice's UPDATED commitment to secret value 999";
    let start = Instant::now();
    tree.update(0, new_commitment.as_bytes())?;
    let duration = start.elapsed();
    println!(
        "   Updated index 0 with: '{}' (took {:?})",
        new_commitment, duration
    );
    println!("   New root: {}", hex::encode(tree.root()));

    // Sync to disk
    println!("\n💾 Syncing to disk...");
    let start = Instant::now();
    tree.sync()?;
    let duration = start.elapsed();
    println!("   Sync completed in {:?}", duration);

    // Demonstrate serialization options
    println!("\n📦 Testing serialization formats...");
    let in_memory_tree = IncrementalMerkleTree::new();
    let mut test_tree = in_memory_tree;
    for commitment in &commitments {
        test_tree.append(commitment.as_bytes())?;
    }

    let formats = vec![
        ("Bincode", SerializationFormat::Bincode),
        ("MessagePack", SerializationFormat::MessagePack),
        ("Postcard", SerializationFormat::Postcard),
    ];

    for (name, format) in formats {
        let options_uncompressed = SerializationOptions {
            format: format.clone(),
            compress: false,
            compression_level: 6,
        };

        let options_compressed = SerializationOptions {
            format,
            compress: true,
            compression_level: 6,
        };

        let uncompressed = serialize_tree_optimized(&test_tree, &options_uncompressed)?;
        let compressed = serialize_tree_optimized(&test_tree, &options_compressed)?;

        println!(
            "   {}: {} bytes (uncompressed), {} bytes (compressed)",
            name,
            uncompressed.len(),
            compressed.len()
        );
    }

    // Demonstrate delta serialization
    println!("\n🔄 Testing delta serialization...");
    let mut tree1 = IncrementalMerkleTree::new();
    tree1.append(b"original1")?;
    tree1.append(b"original2")?;

    let mut tree2 = tree1.clone();
    tree2.append(b"new1")?;
    tree2.append(b"new2")?;
    tree2.update(0, b"updated_original1")?;

    let delta = tree1.create_delta(&tree2);
    let delta_options = SerializationOptions::default();
    let serialized_delta = serialize_tree_delta(&delta, &delta_options)?;

    println!(
        "   Delta: {} new leaves, {} updated leaves",
        delta.new_leaves.len(),
        delta.updated_leaves.len()
    );
    println!("   Serialized delta size: {} bytes", serialized_delta.len());

    // Show file system usage
    println!("\n📂 File system usage:");
    if let Ok(entries) = std::fs::read_dir("./demo_data") {
        for entry in entries {
            if let Ok(entry) = entry {
                if let Ok(metadata) = entry.metadata() {
                    println!(
                        "   {}: {} bytes",
                        entry.file_name().to_string_lossy(),
                        metadata.len()
                    );
                }
            }
        }
    }

    // Test persistence by reopening
    println!("\n🔄 Testing persistence by reopening tree...");
    drop(tree); // Close the current tree

    let start = Instant::now();
    let reopened_tree = PersistentMerkleTree::new(StorageConfig {
        data_dir: std::path::PathBuf::from("./demo_data"),
        cache_size: 512 * 1024,
        sync_interval: std::time::Duration::from_secs(2),
        compression: true,
        enable_wal: true,
    })?;
    let duration = start.elapsed();

    println!("   Reopened tree in {:?}", duration);
    println!("   Length: {} leaves", reopened_tree.len());
    println!("   Root: {}", hex::encode(reopened_tree.root()));

    // Verify we can still generate proofs after reopening
    if reopened_tree.len() > 0 {
        let proof = reopened_tree.prove(0)?;
        let is_valid = IncrementalMerkleTree::verify_proof(
            &proof.leaf,
            proof.leaf_index,
            &proof.siblings,
            &reopened_tree.root(),
        );
        println!(
            "   First leaf proof verification: {}",
            if is_valid { "✅ VALID" } else { "❌ INVALID" }
        );
    }

    println!("\n🎉 Demo completed successfully!");
    println!("💡 The tree data is persisted in './demo_data' directory");
    println!("   Run this demo again to see the tree state restored from disk!");

    Ok(())
}
