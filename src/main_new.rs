use arcium_indexer::{
    IndexerConfig, PersistentMerkleTree, StorageConfig, 
    serialization::{serialize_tree_optimized, SerializationOptions, SerializationFormat},
    tree::{Commitment, IncrementalMerkleTree, TreeDelta},
};
use std::time::Instant;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🌳 Arcium Indexer - File-Based Merkle Tree Demo");
    println!("================================================\n");

    // Run the demo
    run_persistent_demo()?;
    
    println!("\n" + "=".repeat(50).as_str());
    
    run_serialization_demo()?;
    
    println!("\n🎉 Demo completed successfully!");
    println!("💡 Check the './demo_data' directory to see persisted files");
    
    Ok(())
}

fn run_persistent_demo() -> Result<(), Box<dyn std::error::Error>> {
    println!("📁 Persistent Storage Demo");
    println!("-".repeat(30));

    // Create storage configuration
    let config = StorageConfig::new("./demo_data")
        .with_cache_size(512 * 1024) // 512KB cache
        .with_compression(true)
        .with_wal(true);

    println!("Config: {:?}", config);

    // Create or open persistent tree
    println!("\n🔧 Creating/Opening persistent Merkle tree...");
    let start = Instant::now();
    let mut tree = PersistentMerkleTree::new(config)?;
    println!("✅ Tree initialized in {:?}", start.elapsed());

    // Show initial state
    println!("\n📊 Initial tree state:");
    println!("   Length: {} leaves", tree.len());
    println!("   Root: {}", hex::encode(tree.root()));
    if let Some(zero_hash) = tree.zero_hash(0) {
        println!("   Zero hash (level 0): {}", hex::encode(zero_hash));
    }

    // Add some commitments
    println!("\n📝 Adding commitments to the tree...");
    let commitments = [
        "Alice's commitment to secret value 123",
        "Bob's commitment to secret value 456",
        "Charlie's commitment to secret value 789",
    ];

    let mut indices = Vec::new();
    for (i, commitment) in commitments.iter().enumerate() {
        let start = Instant::now();
        let index = tree.append(commitment.as_bytes())?;
        let duration = start.elapsed();
        
        indices.push(index);
        println!("   [{}] Added: '{}' (took {:?})", index, commitment, duration);
    }

    // Show updated state
    println!("\n📊 Updated tree state:");
    println!("   Length: {} leaves", tree.len());
    println!("   Root: {}", hex::encode(tree.root()));

    // Generate proofs
    println!("\n🔍 Generating Merkle proofs...");
    for &index in &indices {
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
        let is_valid = proof.verify(&tree.root());
        println!(
            "     Verification: {}",
            if is_valid { "✅ VALID" } else { "❌ INVALID" }
        );
    }

    // Sync to disk
    println!("\n💾 Syncing to disk...");
    let start = Instant::now();
    tree.sync()?;
    let duration = start.elapsed();
    println!("   Sync completed in {:?}", duration);

    Ok(())
}

fn run_serialization_demo() -> Result<(), Box<dyn std::error::Error>> {
    println!("📦 Serialization Demo");
    println!("-".repeat(20));

    // Create a test tree
    let mut tree = IncrementalMerkleTree::new();
    let test_data = [
        "commitment_1", "commitment_2", "commitment_3", 
        "commitment_4", "commitment_5"
    ];

    for data in &test_data {
        tree.append(data.as_bytes())?;
    }

    // Test different serialization formats
    println!("\n🔄 Testing serialization formats:");
    let formats = [
        ("Bincode", SerializationFormat::Bincode),
        ("MessagePack", SerializationFormat::MessagePack),
        ("Postcard", SerializationFormat::Postcard),
    ];

    for (name, format) in &formats {
        let options_uncompressed = SerializationOptions::new(format.clone(), false, 0);
        let options_compressed = SerializationOptions::new(format.clone(), true, 6);

        let uncompressed = serialize_tree_optimized(&tree, &options_uncompressed)?;
        let compressed = serialize_tree_optimized(&tree, &options_compressed)?;
        
        println!(
            "   {}: {} bytes (uncompressed), {} bytes (compressed)",
            name,
            uncompressed.len(),
            compressed.len()
        );
    }

    // Test delta serialization
    println!("\n🔄 Testing delta serialization:");
    let mut tree1 = IncrementalMerkleTree::new();
    tree1.append(b"original1")?;
    tree1.append(b"original2")?;

    let mut tree2 = tree1.clone();
    tree2.append(b"new1")?;
    tree2.append(b"new2")?;
    tree2.update(0, b"updated_original1")?;

    let delta = tree1.create_delta(&tree2);
    println!(
        "   Delta: {} new leaves, {} updated leaves, {} total changes",
        delta.new_leaves.len(),
        delta.updated_leaves.len(),
        delta.change_count()
    );

    Ok(())
}

fn _test_commitment_parsing() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🔍 Testing commitment parsing:");
    
    let commitment = Commitment::new(1, 42, [1u8; 32], [2u8; 32], [3u8; 32]);
    let serialized = commitment.to_bytes();
    let parsed = Commitment::from_bytes(&serialized)?;
    
    println!("   Original: {:?}", commitment);
    println!("   Parsed:   {:?}", parsed);
    println!("   Match: {}", 
             commitment.version == parsed.version &&
             commitment.commitment_index == parsed.commitment_index &&
             commitment.hash == parsed.hash);
    
    Ok(())
}
