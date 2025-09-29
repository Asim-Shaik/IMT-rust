use serde::{Deserialize, Serialize};

use crate::errors::{IndexerError, IndexerResult};
use crate::utils::Hash;

/// Represents a commitment in the Merkle tree
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Commitment {
    pub version: u32,
    pub commitment_index: u64,
    pub hash: Hash,
    pub random_secret: Hash,
    pub nullifier: Hash,
}

impl Commitment {
    /// Create a new commitment
    pub fn new(
        version: u32,
        commitment_index: u64,
        hash: Hash,
        random_secret: Hash,
        nullifier: Hash,
    ) -> Self {
        Self {
            version,
            commitment_index,
            hash,
            random_secret,
            nullifier,
        }
    }

    /// Parse a commitment from raw binary data
    /// Expected format: version(4) + commitment_index(8) + hash(32) + random_secret(32) + nullifier(32)
    pub fn from_bytes(data: &[u8]) -> IndexerResult<Self> {
        const EXPECTED_SIZE: usize = 4 + 8 + 32 + 32 + 32;

        if data.len() < EXPECTED_SIZE {
            return Err(IndexerError::InvalidData(format!(
                "insufficient data for commitment: expected {} bytes, got {}",
                EXPECTED_SIZE,
                data.len()
            )));
        }

        let mut offset = 0;

        // Parse version (4 bytes, little-endian)
        let version = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        offset += 4;

        // Parse commitment_index (8 bytes, little-endian)
        let commitment_index = u64::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        offset += 8;

        // Parse hash (32 bytes)
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        // Parse random_secret (32 bytes)
        let mut random_secret = [0u8; 32];
        random_secret.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        // Parse nullifier (32 bytes)
        let mut nullifier = [0u8; 32];
        nullifier.copy_from_slice(&data[offset..offset + 32]);

        Ok(Self::new(
            version,
            commitment_index,
            hash,
            random_secret,
            nullifier,
        ))
    }

    /// Convert commitment to binary format
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(4 + 8 + 32 + 32 + 32);

        data.extend_from_slice(&self.version.to_le_bytes());
        data.extend_from_slice(&self.commitment_index.to_le_bytes());
        data.extend_from_slice(&self.hash);
        data.extend_from_slice(&self.random_secret);
        data.extend_from_slice(&self.nullifier);

        data
    }
}
