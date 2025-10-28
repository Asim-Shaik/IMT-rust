use std::fmt;

/// Custom error types for the Merkle tree indexer
#[derive(Debug)]
pub enum IndexerError {
    /// Tree is at full capacity
    TreeFull,
    /// Index is out of bounds
    IndexOutOfBounds,
    /// Leaf not yet appended
    LeafNotAppended,
    /// Serialization failed
    SerializationError(String),
    /// IO operation failed
    IoError(std::io::Error),
    /// Checksum verification failed
    ChecksumError,
    /// Invalid data format
    InvalidData(String),
    /// Storage operation failed
    StorageError(String),
    /// Feature not yet implemented
    NotImplemented(String),
}

impl fmt::Display for IndexerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IndexerError::TreeFull => write!(f, "Merkle tree is at full capacity"),
            IndexerError::IndexOutOfBounds => write!(f, "Index is out of bounds"),
            IndexerError::LeafNotAppended => write!(f, "Leaf has not been appended yet"),
            IndexerError::SerializationError(msg) => write!(f, "Serialization error: {msg}"),
            IndexerError::IoError(err) => write!(f, "IO error: {err}"),
            IndexerError::ChecksumError => write!(f, "Checksum verification failed"),
            IndexerError::InvalidData(msg) => write!(f, "Invalid data: {msg}"),
            IndexerError::StorageError(msg) => write!(f, "Storage error: {msg}"),
            IndexerError::NotImplemented(msg) => write!(f, "Feature not implemented: {msg}"),
        }
    }
}

impl std::error::Error for IndexerError {}

impl From<std::io::Error> for IndexerError {
    fn from(err: std::io::Error) -> Self {
        IndexerError::IoError(err)
    }
}

impl From<bincode::Error> for IndexerError {
    fn from(err: bincode::Error) -> Self {
        IndexerError::SerializationError(err.to_string())
    }
}

impl From<Box<dyn std::error::Error>> for IndexerError {
    fn from(err: Box<dyn std::error::Error>) -> Self {
        IndexerError::StorageError(err.to_string())
    }
}

impl From<hex::FromHexError> for IndexerError {
    fn from(err: hex::FromHexError) -> Self {
        IndexerError::InvalidData(format!("Hex decoding error: {err}"))
    }
}

/// Result type alias for indexer operations
pub type IndexerResult<T> = Result<T, IndexerError>;
