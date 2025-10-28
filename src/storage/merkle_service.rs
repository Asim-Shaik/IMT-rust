use crate::errors::IndexerResult;
use crate::storage::{create_tree_storage, TreeStorage, TreeType};
use crate::tree::{Commitment, MerkleProof};
use std::path::Path;

/// Facade to simplify working with the Merkle tree storage from the indexer.
pub struct MerkleTreeService {
    storage: Box<dyn TreeStorage + Send + 'static>,
}

impl MerkleTreeService {
    pub fn new<P: AsRef<Path>>(data_dir: P, depth: Option<usize>) -> IndexerResult<Self> {
        let storage = create_tree_storage(TreeType::Incremental, data_dir.as_ref(), depth)?;
        Ok(Self { storage })
    }

    pub fn insert_commitment(&mut self, commitment: &Commitment) -> IndexerResult<()> {
        self.storage.insert_commitment(commitment)
    }

    pub fn root(&self) -> [u8; 32] {
        self.storage.root()
    }

    pub fn len(&self) -> usize {
        self.storage.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn save(&mut self) -> IndexerResult<()> {
        self.storage.save()
    }

    /// Generate a Merkle proof (root path) for a leaf at the given index
    pub fn prove(&self, index: usize) -> IndexerResult<MerkleProof> {
        self.storage.prove(index)
    }
}
