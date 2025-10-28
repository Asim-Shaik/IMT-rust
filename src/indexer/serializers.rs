use crate::errors::{IndexerError, IndexerResult};
use crate::tree::Commitment;
use borsh::BorshDeserialize;
// use serde::Deserialize; // kept commented unless needed by user types
use std::collections::HashMap;

// Define a trait that all instruction serializers implement
pub trait InstructionSerializer: Send + Sync {
    fn serialize(&self, ix_data: &[u8]) -> IndexerResult<Option<Commitment>>;
}

// Example: a Borsh-based serializer for a specific instruction
pub struct BorshCommitmentSerializer<S> {
    _phantom: std::marker::PhantomData<S>,
}

impl<S> Default for BorshCommitmentSerializer<S> {
    fn default() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<S> BorshCommitmentSerializer<S>
where
    S: BorshDeserialize + Into<Commitment>,
{
    pub fn new() -> Self {
        Self::default()
    }
}

impl<S> InstructionSerializer for BorshCommitmentSerializer<S>
where
    S: BorshDeserialize + Into<Commitment> + Send + Sync,
{
    fn serialize(&self, ix_data: &[u8]) -> IndexerResult<Option<Commitment>> {
        let parsed = S::try_from_slice(ix_data)
            .map_err(|e| IndexerError::InvalidData(format!("borsh parse error: {e}")))?;
        Ok(Some(parsed.into()))
    }
}

// Registry keyed by instruction discriminator (e.g., first byte(s) of ix data)
pub struct SerializerRegistry {
    serializers: HashMap<Vec<u8>, Box<dyn InstructionSerializer>>, // key: discriminator bytes
}

impl SerializerRegistry {
    pub fn new() -> Self {
        Self {
            serializers: HashMap::new(),
        }
    }

    pub fn register(&mut self, discriminator: Vec<u8>, serializer: Box<dyn InstructionSerializer>) {
        self.serializers.insert(discriminator, serializer);
    }

    pub fn parse(&self, ix_data: &[u8]) -> IndexerResult<Option<Commitment>> {
        // Simple example: use first 8 bytes as discriminator, fallback to full
        let key = if ix_data.len() >= 8 {
            ix_data[..8].to_vec()
        } else {
            ix_data.to_vec()
        };
        if let Some(serializer) = self.serializers.get(&key) {
            serializer.serialize(ix_data)
        } else {
            Ok(None)
        }
    }
}

impl Default for SerializerRegistry {
    fn default() -> Self {
        Self::new()
    }
}
