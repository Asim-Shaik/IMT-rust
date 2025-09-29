use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use std::io::{Read, Write};

use crate::errors::{IndexerError, IndexerResult};
use crate::serialization::{SerializationFormat, SerializationOptions};
use crate::tree::TreeDelta;

/// Serialize a tree delta using the specified options
pub fn serialize_tree_delta(
    delta: &TreeDelta,
    options: &SerializationOptions,
) -> IndexerResult<Vec<u8>> {
    let serialized = match options.format {
        SerializationFormat::Bincode => {
            bincode::serialize(delta)
                .map_err(|e| IndexerError::SerializationError(e.to_string()))?
        }
        SerializationFormat::MessagePack => {
            rmp_serde::to_vec(delta)
                .map_err(|e| IndexerError::SerializationError(e.to_string()))?
        }
        SerializationFormat::Postcard => {
            let mut buffer = vec![0u8; 1024 * 1024]; // 1MB buffer should be enough for deltas
            let slice = postcard::to_slice(delta, &mut buffer)
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

/// Deserialize a tree delta using the specified options
pub fn deserialize_tree_delta(
    data: &[u8],
    options: &SerializationOptions,
) -> IndexerResult<TreeDelta> {
    let decompressed = if options.compress {
        let mut decoder = GzDecoder::new(data);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed)?;
        decompressed
    } else {
        data.to_vec()
    };

    let delta = match options.format {
        SerializationFormat::Bincode => {
            bincode::deserialize(&decompressed)
                .map_err(|e| IndexerError::SerializationError(e.to_string()))?
        }
        SerializationFormat::MessagePack => {
            rmp_serde::from_slice(&decompressed)
                .map_err(|e| IndexerError::SerializationError(e.to_string()))?
        }
        SerializationFormat::Postcard => {
            postcard::from_bytes(&decompressed)
                .map_err(|e| IndexerError::SerializationError(e.to_string()))?
        }
    };

    Ok(delta)
}
