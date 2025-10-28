use std::path::Path;
use std::sync::{Arc, RwLock};

use crate::errors::{IndexerError, IndexerResult};
use crate::tree::{Commitment, IncrementalMerkleTree, MerkleProof};
use crate::utils::Hash;

/// Unified trait for incremental merkle tree storage
pub trait TreeStorage: Send {
    /// Get the root hash of the tree
    fn root(&self) -> Hash;

    /// Get the number of elements in the tree
    fn len(&self) -> usize;

    /// Check if the tree is empty
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Insert a commitment into the tree
    fn insert_commitment(&mut self, commitment: &Commitment) -> IndexerResult<()>;

    /// Get a commitment by index
    fn get_commitment(&self, commitment_index: u64) -> IndexerResult<Option<Commitment>>;

    /// Generate a Merkle proof for a given index
    fn prove(&self, index: usize) -> IndexerResult<MerkleProof>;

    /// Save the tree to persistent storage
    fn save(&self) -> IndexerResult<()>;

    /// Get tree statistics
    fn stats(&self) -> TreeStats;
}

/// Statistics about a tree
#[derive(Clone, Debug)]
pub struct TreeStats {
    pub root_hash: Hash,
    pub tree_size: usize,
    pub tree_type: TreeType,
}

/// Type of merkle tree
#[derive(Clone, Debug, PartialEq)]
pub enum TreeType {
    Incremental,
}

/// Unified storage for incremental merkle trees
pub struct IncrementalTreeStorage {
    tree: Arc<RwLock<IncrementalMerkleTree>>,
    data_path: std::path::PathBuf,
    metadata_path: std::path::PathBuf,
}

impl IncrementalTreeStorage {
    /// Create or open an incremental tree storage
    pub fn new<P: AsRef<Path>>(data_dir: P, depth: Option<usize>) -> IndexerResult<Self> {
        let data_dir = data_dir.as_ref();
        std::fs::create_dir_all(data_dir)?;

        let data_path = data_dir.join("incremental_tree.dat");
        let metadata_path = data_dir.join("incremental_tree_metadata.dat");

        // Try to load existing tree, otherwise create new one
        let tree = if data_path.exists() {
            Self::load_tree(&data_path, depth.unwrap_or(crate::tree::DEFAULT_TREE_DEPTH))?
        } else {
            IncrementalMerkleTree::with_depth(depth.unwrap_or(crate::tree::DEFAULT_TREE_DEPTH))
        };

        Ok(Self {
            tree: Arc::new(RwLock::new(tree)),
            data_path,
            metadata_path,
        })
    }

    /// Load a tree from disk
    fn load_tree(path: &Path, depth: usize) -> IndexerResult<IncrementalMerkleTree> {
        use bincode::deserialize;
        use std::fs::File;
        use std::io::{BufReader, Read};

        let file = File::open(path)?;
        let mut reader = BufReader::new(file);
        let mut data = Vec::new();
        reader.read_to_end(&mut data)?;

        if data.is_empty() {
            return Ok(IncrementalMerkleTree::with_depth(depth));
        }

        // Try bincode deserialization first
        match deserialize::<IncrementalMerkleTree>(&data) {
            Ok(mut tree) => {
                // Rebuild frontier after deserialization (it's marked with #[serde(skip)])
                tree.rebuild_frontier().map_err(|e| {
                    IndexerError::StorageError(format!("Failed to rebuild frontier: {}", e))
                })?;
                Ok(tree)
            }
            Err(e) => {
                eprintln!("Failed to deserialize incremental tree: {e}");
                // If bincode fails, create a new tree
                Ok(IncrementalMerkleTree::with_depth(depth))
            }
        }
    }

    /// Save the tree to disk
    fn save_tree(&self) -> IndexerResult<()> {
        use bincode::serialize;
        use std::fs::OpenOptions;
        use std::io::{BufWriter, Write};

        let tree = self.tree.read().unwrap();
        let data = serialize(&*tree)?;

        // Write tree data
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&self.data_path)?;
        let mut writer = BufWriter::new(file);
        writer.write_all(&data)?;
        writer.flush()?;

        // Write metadata (root hash)
        let metadata = IncrementalTreeMetadata {
            root_hash: tree.root(),
            version: 1,
        };
        let metadata_data = serialize(&metadata)?;
        let metadata_file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&self.metadata_path)?;
        let mut metadata_writer = BufWriter::new(metadata_file);
        metadata_writer.write_all(&metadata_data)?;
        metadata_writer.flush()?;

        Ok(())
    }
}

impl TreeStorage for IncrementalTreeStorage {
    fn root(&self) -> Hash {
        let tree = self.tree.read().unwrap();
        tree.root()
    }

    fn len(&self) -> usize {
        let tree = self.tree.read().unwrap();
        tree.len()
    }

    fn insert_commitment(&mut self, commitment: &Commitment) -> IndexerResult<()> {
        let mut tree = self.tree.write().unwrap();
        tree.insert_commitment(commitment)?;
        Ok(())
    }

    fn get_commitment(&self, _commitment_index: u64) -> IndexerResult<Option<Commitment>> {
        // For incremental trees, we need to reconstruct the commitment from the stored data
        // This is a simplified implementation
        Err(IndexerError::NotImplemented(
            "Commitment retrieval not yet implemented for incremental trees".to_string(),
        ))
    }

    fn prove(&self, index: usize) -> IndexerResult<MerkleProof> {
        let tree = self.tree.read().unwrap();
        tree.prove(index)
    }

    fn save(&self) -> IndexerResult<()> {
        self.save_tree()
    }

    fn stats(&self) -> TreeStats {
        let tree = self.tree.read().unwrap();
        TreeStats {
            root_hash: tree.root(),
            tree_size: tree.len(),
            tree_type: TreeType::Incremental,
        }
    }
}

/// Metadata for incremental trees
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct IncrementalTreeMetadata {
    pub root_hash: Hash,
    pub version: u32,
}

/// Factory function to create tree storage based on type
pub fn create_tree_storage<P: AsRef<Path>>(
    tree_type: TreeType,
    data_dir: P,
    depth: Option<usize>,
) -> IndexerResult<Box<dyn TreeStorage>> {
    match tree_type {
        TreeType::Incremental => {
            let storage = IncrementalTreeStorage::new(data_dir, depth)?;
            Ok(Box::new(storage))
        }
    }
}
