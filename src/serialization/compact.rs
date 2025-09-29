use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

use crate::errors::{IndexerError, IndexerResult};
use crate::serialization::{SerializationFormat, SerializationOptions};
use crate::tree::IncrementalMerkleTree;
use crate::utils::Hash;

/// Compact representation of a Merkle tree that only stores non-empty leaves
#[derive(Serialize, Deserialize)]
pub struct CompactTree {
    next_index: usize,
    /// Store only non-empty leaves as (index, hash) pairs
    non_empty_leaves: Vec<(usize, Hash)>,
}

impl From<&IncrementalMerkleTree> for CompactTree {
    fn from(tree: &IncrementalMerkleTree) -> Self {
        let non_empty_leaves: Vec<(usize, Hash)> = (0..tree.len())
            .filter_map(|i| tree.get_leaf_hash(i).map(|hash| (i, hash)))
            .collect();

        CompactTree {
            next_index: tree.len(),
            non_empty_leaves,
        }
    }
}

impl CompactTree {
    /// Convert back to a full incremental Merkle tree
    pub fn to_tree(&self) -> IndexerResult<IncrementalMerkleTree> {
        let mut tree = IncrementalMerkleTree::new();

        // Restore the leaves directly using the new API
        for (index, hash) in &self.non_empty_leaves {
            tree.set_leaf_hash(*index, *hash)?;
        }

        // Set the correct next_index
        tree.set_next_index(self.next_index)?;

        Ok(tree)
    }
}

/// Serialize a tree using the most compact representation
pub fn serialize_tree_optimized(
    tree: &IncrementalMerkleTree,
    options: &SerializationOptions,
) -> IndexerResult<Vec<u8>> {
    // For now, use the standard tree serialization
    // In a full implementation, we'd use CompactTree
    let serialized =
        match options.format {
            SerializationFormat::Bincode => bincode::serialize(tree)
                .map_err(|e| IndexerError::SerializationError(e.to_string()))?,
            SerializationFormat::MessagePack => rmp_serde::to_vec(tree)
                .map_err(|e| IndexerError::SerializationError(e.to_string()))?,
            SerializationFormat::Postcard => {
                let mut buffer = vec![0u8; 4 * 1024 * 1024]; // 4MB buffer
                let slice = postcard::to_slice(tree, &mut buffer)
                    .map_err(|e| IndexerError::SerializationError(e.to_string()))?;
                slice.to_vec()
            }
        };

    if options.compress {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::new(options.compression_level));
        encoder.write_all(&serialized)?;
        Ok(encoder.finish()?)
    } else {
        Ok(serialized)
    }
}

/// Deserialize a tree from optimized format
pub fn deserialize_tree_optimized(
    data: &[u8],
    options: &SerializationOptions,
) -> IndexerResult<IncrementalMerkleTree> {
    let decompressed = if options.compress {
        let mut decoder = GzDecoder::new(data);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed)?;
        decompressed
    } else {
        data.to_vec()
    };

    let compact_tree: CompactTree = match options.format {
        SerializationFormat::Bincode => bincode::deserialize(&decompressed)
            .map_err(|e| IndexerError::SerializationError(e.to_string()))?,
        SerializationFormat::MessagePack => rmp_serde::from_slice(&decompressed)
            .map_err(|e| IndexerError::SerializationError(e.to_string()))?,
        SerializationFormat::Postcard => postcard::from_bytes(&decompressed)
            .map_err(|e| IndexerError::SerializationError(e.to_string()))?,
    };

    compact_tree.to_tree()
}
