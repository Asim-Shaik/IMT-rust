use serde::{Deserialize, Serialize};

use crate::errors::{IndexerError, IndexerResult};
use crate::utils::Hash;

/// Metadata stored on disk for the persistent tree
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TreeMetadata {
    /// Format version for compatibility
    pub version: u32,
    /// Tree depth
    pub depth: usize,
    /// Number of leaves currently in the tree
    pub next_index: usize,
    /// Current root hash
    pub root_hash: Hash,
    /// Timestamp of last sync
    pub last_sync: u64,
    /// Checksum for integrity verification
    pub checksum: u32,
}

impl TreeMetadata {
    /// Create new metadata
    pub fn new(depth: usize, next_index: usize, root_hash: Hash) -> Self {
        let mut metadata = Self {
            version: 1,
            depth,
            next_index,
            root_hash,
            last_sync: current_timestamp(),
            checksum: 0,
        };

        metadata.update_checksum();
        metadata
    }

    /// Update the checksum based on current data
    pub fn update_checksum(&mut self) {
        self.last_sync = current_timestamp();
        let data_for_checksum = (
            self.version,
            self.depth,
            self.next_index,
            self.root_hash,
            self.last_sync,
        );
        
        if let Ok(serialized) = bincode::serialize(&data_for_checksum) {
            self.checksum = crc32fast::hash(&serialized);
        }
    }

    /// Verify the checksum is correct
    pub fn verify_checksum(&self) -> IndexerResult<()> {
        let data_for_checksum = (
            self.version,
            self.depth,
            self.next_index,
            self.root_hash,
            self.last_sync,
        );
        
        let serialized = bincode::serialize(&data_for_checksum)
            .map_err(|e| IndexerError::SerializationError(e.to_string()))?;
        
        let calculated_checksum = crc32fast::hash(&serialized);
        
        if calculated_checksum == self.checksum {
            Ok(())
        } else {
            Err(IndexerError::ChecksumError)
        }
    }

    /// Update metadata with new tree state
    pub fn update(&mut self, next_index: usize, root_hash: Hash) {
        self.next_index = next_index;
        self.root_hash = root_hash;
        self.update_checksum();
    }
}

/// Get current Unix timestamp
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
