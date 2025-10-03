use std::collections::HashMap;
use umbra_indexer::tree::{
    kv_trait::AuthenticatedKV,
    sparse_merkle_tree::{smt_utils, SerializableNode, SparseMerkleTree},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Sparse Merkle Tree Inspector");
    println!("============================");

    // Create a tree with some test data
    let mut tree = SparseMerkleTree::new();
    let test_data = vec![
        ("user1", "Alice"),
        ("user2", "Bob"),
        ("user3", "Charlie"),
        ("user4", "Diana"),
        ("user5", "Eve"),
    ];

    println!("\nInserting test data...");
    for (key, value) in &test_data {
        tree = tree.insert(key.to_string(), value.to_string());
        println!("  Inserted: {} -> {}", key, value);
    }

    // Inspect the tree structure
    println!("\nTree Structure Analysis:");
    println!("========================");

    let stats = analyze_tree_structure(&tree);
    print_tree_stats(&stats);

    println!("\nDetailed Tree Structure:");
    println!("========================");
    print_tree_structure(&tree.serializable.root, 0, "");

    println!("\nHash Analysis:");
    println!("==============");
    analyze_hashes(&tree);

    println!("\nProof Analysis:");
    println!("===============");
    analyze_proofs(&tree, &test_data);

    Ok(())
}

#[derive(Debug)]
struct TreeStats {
    total_nodes: usize,
    leaf_nodes: usize,
    branch_nodes: usize,
    empty_nodes: usize,
    max_depth: usize,
    node_depths: HashMap<usize, usize>,
}

fn analyze_tree_structure(tree: &SparseMerkleTree) -> TreeStats {
    let mut stats = TreeStats {
        total_nodes: 0,
        leaf_nodes: 0,
        branch_nodes: 0,
        empty_nodes: 0,
        max_depth: 0,
        node_depths: HashMap::new(),
    };

    analyze_node(&tree.serializable.root, 0, &mut stats);
    stats
}

fn analyze_node(node: &SerializableNode, depth: usize, stats: &mut TreeStats) {
    stats.total_nodes += 1;
    stats.max_depth = stats.max_depth.max(depth);
    *stats.node_depths.entry(depth).or_insert(0) += 1;

    match node {
        SerializableNode::Empty => {
            stats.empty_nodes += 1;
        }
        SerializableNode::Leaf { .. } => {
            stats.leaf_nodes += 1;
        }
        SerializableNode::Branch { left, right, .. } => {
            stats.branch_nodes += 1;
            analyze_node(left, depth + 1, stats);
            analyze_node(right, depth + 1, stats);
        }
    }
}

fn print_tree_stats(stats: &TreeStats) {
    println!("  Total nodes: {}", stats.total_nodes);
    println!("  Leaf nodes: {}", stats.leaf_nodes);
    println!("  Branch nodes: {}", stats.branch_nodes);
    println!("  Empty nodes: {}", stats.empty_nodes);
    println!("  Maximum depth: {}", stats.max_depth);

    println!("  Node distribution by depth:");
    for depth in 0..=stats.max_depth {
        if let Some(&count) = stats.node_depths.get(&depth) {
            println!("    Depth {}: {} nodes", depth, count);
        }
    }
}

fn print_tree_structure(node: &SerializableNode, depth: usize, prefix: &str) {
    let indent = "  ".repeat(depth);

    match node {
        SerializableNode::Empty => {
            println!("{}{}EMPTY", prefix, indent);
        }
        SerializableNode::Leaf { key, value } => {
            println!("{}{}LEAF: {} -> {}", prefix, indent, key, value);
        }
        SerializableNode::Branch { left, right, hash } => {
            println!("{}{}BRANCH: {}", prefix, indent, hex::encode(hash));
            print_tree_structure(left, depth + 1, prefix);
            print_tree_structure(right, depth + 1, prefix);
        }
    }
}

fn analyze_hashes(tree: &SparseMerkleTree) {
    println!("  Root digest: {}", hex::encode(tree.root_digest.as_ref()));

    // Check if root matches the serializable tree's hash
    let serializable_hash = tree.serializable.root.get_hash();
    println!(
        "  Serializable root hash: {}",
        hex::encode(serializable_hash.as_ref())
    );

    if tree.root_digest == serializable_hash {
        println!("  ✓ Root hashes match between runtime and serializable representations");
    } else {
        println!("  ✗ Root hashes don't match!");
    }

    // Analyze leaf hashes
    println!("  Leaf hashes:");
    analyze_node_hashes(&tree.serializable.root, 0, "");
}

fn analyze_node_hashes(node: &SerializableNode, depth: usize, prefix: &str) {
    let indent = "  ".repeat(depth);

    match node {
        SerializableNode::Empty => {
            println!("{}{}EMPTY: {}", prefix, indent, hex::encode([0u8; 32]));
        }
        SerializableNode::Leaf { key, value } => {
            let hash = smt_utils::hash_kv(key, value);
            println!(
                "{}{}LEAF {}: {}",
                prefix,
                indent,
                key,
                hex::encode(hash.as_ref())
            );
        }
        SerializableNode::Branch { left, right, hash } => {
            println!("{}{}BRANCH: {}", prefix, indent, hex::encode(hash));
            analyze_node_hashes(left, depth + 1, prefix);
            analyze_node_hashes(right, depth + 1, prefix);
        }
    }
}

fn analyze_proofs(tree: &SparseMerkleTree, test_data: &[(&str, &str)]) {
    let commitment = tree.commit();

    for (key, expected_value) in test_data {
        let (value, proof) = tree.get(key.to_string());

        println!("  Key: {}", key);
        println!("    Value: {:?}", value);
        println!(
            "    Proof length: {} sibling hashes",
            proof.sibling_hashes.len()
        );

        // Verify the proof
        let is_valid =
            SparseMerkleTree::check_proof(key.to_string(), value.clone(), &proof, &commitment);

        if is_valid.is_some() {
            println!("    ✓ Proof is valid");
        } else {
            println!("    ✗ Proof is invalid!");
        }

        // Show sibling hashes
        for (i, sibling) in proof.sibling_hashes.iter().enumerate() {
            println!("      Sibling {}: {}", i, hex::encode(sibling.as_ref()));
        }
        println!();
    }
}
