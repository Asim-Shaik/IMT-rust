use std::env;
use umbra_indexer::indexer::service::IndexService;
use umbra_indexer::tree::{Commitment, IncrementalMerkleTree};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // init logger
    env_logger::builder().format_timestamp_secs().init();

    // Run Merkle proof example
    run_merkle_proof_example()?;
    println!("🌳 Umbra Indexer - Starting...");
    println!("================================\n");

    // Read configuration from environment variables
    let data_dir = env::var("INDEXER_DATA_DIR").unwrap_or_else(|_| "./data".to_string());
    let depth = env::var("INDEXER_TREE_DEPTH")
        .ok()
        .and_then(|v| v.parse::<usize>().ok());
    let laserstream_endpoint = env::var("LASERSTREAM_ENDPOINT")
        .unwrap_or_else(|_| "https://laserstream-mainnet-tyo.helius-rpc.com".to_string());
    let laserstream_api_key =
        env::var("LASERSTREAM_API_KEY").unwrap_or_else(|_| "your-api-key".to_string());
    let program_ids: Vec<String> = env::var("PROGRAM_IDS")
        .unwrap_or_else(|_| "YourProgram111111111111111111111111111111111".to_string())
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();

    // Print configuration
    println!("📋 Configuration:");
    println!("   Data Directory: {data_dir}");
    println!("   Tree Depth: {:?}", depth.unwrap_or(20));
    println!("   Laserstream Endpoint: {laserstream_endpoint}");
    println!(
        "   Laserstream API Key: {}",
        if laserstream_api_key.len() > 10 {
            format!("{}...", &laserstream_api_key[..10])
        } else {
            "***".to_string()
        }
    );
    println!("   Program IDs: {program_ids:?}");
    println!();

    // Initialize tree (will load existing or create new)
    println!("🌳 Initializing Merkle tree...");
    println!("   Directory: {data_dir}");

    // Create serializer registry
    let registry = umbra_indexer::indexer::serializers::SerializerRegistry::new();

    println!("✅ Tree ready (will load if exists, or create new)\n");

    // Start the indexer service
    println!("🚀 Starting indexer...");
    println!("   Connecting to Laserstream...\n");

    // Run the async indexer service
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        let service = IndexService::new(
            &data_dir,
            depth,
            laserstream_endpoint,
            laserstream_api_key,
            program_ids,
            registry,
        )?;

        println!("✅ Connected! Listening for transactions...\n");
        service.run().await
    })?;

    Ok(())
}

fn run_merkle_proof_example() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n═══════════════════════════════════════════════════════════════");
    println!("🔬 MERKLE PROOF GENERATION EXAMPLE");
    println!("═══════════════════════════════════════════════════════════════\n");

    // Create tree with depth 3 (for easy visualization)
    let mut tree = IncrementalMerkleTree::new(3);
    println!(
        "Tree created with depth=3, capacity=2^3={}\n",
        tree.capacity()
    );

    // Insert 5 commitments (indices 0-4)
    println!("Inserting 5 commitments...");
    let commitments = [
        Commitment::new(1, 0, [0u8; 32], [1u8; 32], [2u8; 32]),
        Commitment::new(1, 1, [10u8; 32], [11u8; 32], [12u8; 32]),
        Commitment::new(1, 2, [20u8; 32], [21u8; 32], [22u8; 32]),
        Commitment::new(1, 3, [30u8; 32], [31u8; 32], [32u8; 32]),
        Commitment::new(1, 4, [40u8; 32], [41u8; 32], [42u8; 32]),
    ];

    for (i, commitment) in commitments.iter().enumerate() {
        let index = tree.insert_commitment(commitment)?;
        println!(
            "  Inserted commitment {} at index {} (root: {})",
            i,
            index,
            hex::encode(tree.root())
                .chars()
                .take(16)
                .collect::<String>()
        );
    }

    println!("\nTree state:");
    println!("  Leaves: {} (indices 0-4)", tree.len());
    println!("  Root: {}", hex::encode(tree.root()));

    // Generate proof for index 2
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Generating proof for leaf at index 2...\n");

    let proof = tree.prove(2)?;

    println!("Proof generated:");
    println!("  Leaf index: {}", proof.leaf_index);
    println!("  Leaf hash: {}", hex::encode(proof.leaf));
    println!("  Number of siblings: {}", proof.siblings.len());

    println!("\nSiblings at each level:");
    for (level, sibling) in proof.siblings.iter().enumerate() {
        println!(
            "  Level {}: {}",
            level,
            hex::encode(sibling).chars().take(16).collect::<String>()
        );
    }

    // Save proof to file as JSON
    let proof_file = "merkle_proof.json";
    let proof_json = serde_json::json!({
        "leaf_index": proof.leaf_index,
        "leaf": hex::encode(proof.leaf),
        "siblings": proof.siblings.iter().map(|s| hex::encode(s)).collect::<Vec<_>>(),
        "sibling_count": proof.siblings.len()
    });
    std::fs::write(proof_file, serde_json::to_string_pretty(&proof_json)?)?;
    println!("\n  Proof saved to: {}", proof_file);
    println!("  Format: JSON");

    // Verify the proof
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Verifying proof...\n");

    let current_root = tree.root();
    println!("  Current root: {}", hex::encode(current_root));

    let is_valid = proof.verify(&current_root);
    println!(
        "  Verification result: {}",
        if is_valid { "✅ VALID" } else { "❌ INVALID" }
    );

    if !is_valid {
        // Manual verification debug
        println!("\n  Debugging proof verification:");
        println!("    Leaf: {}", hex::encode(proof.leaf));
        println!("    Leaf index: {}", proof.leaf_index);
        let mut computed = proof.leaf;
        let mut idx = proof.leaf_index;
        for (i, sibling) in proof.siblings.iter().enumerate() {
            println!(
                "    Level {}: sibling = {}",
                i,
                hex::encode(sibling).chars().take(16).collect::<String>()
            );
            if idx % 2 == 0 {
                computed = umbra_indexer::utils::internal::hash_pair(&computed, sibling);
            } else {
                computed = umbra_indexer::utils::internal::hash_pair(sibling, &computed);
            }
            println!(
                "      Computed: {}",
                hex::encode(computed).chars().take(16).collect::<String>()
            );
            idx /= 2;
        }
        println!("    Final computed root: {}", hex::encode(computed));
    }

    // Display JSON content
    let json_str = std::fs::read_to_string(proof_file)?;
    println!("\nJSON content:");
    println!("{}", json_str);

    println!("\n═══════════════════════════════════════════════════════════════\n");
    Ok(())
}
