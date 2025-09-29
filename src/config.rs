use std::path::PathBuf;
use std::time::Duration;

use crate::serialization::SerializationOptions;
use crate::storage::StorageConfig;

/// Main configuration for the indexer
#[derive(Debug, Clone)]
pub struct IndexerConfig {
    /// Storage configuration
    pub storage: StorageConfig,
    /// Serialization configuration
    pub serialization: SerializationOptions,
    /// Whether to enable debug logging
    pub debug: bool,
}

impl IndexerConfig {
    /// Create a new indexer configuration
    pub fn new<P: Into<PathBuf>>(data_dir: P) -> Self {
        Self {
            storage: StorageConfig::new(data_dir),
            serialization: SerializationOptions::default(),
            debug: false,
        }
    }

    /// Create configuration optimized for development
    pub fn development<P: Into<PathBuf>>(data_dir: P) -> Self {
        Self {
            storage: StorageConfig::new(data_dir)
                .with_cache_size(256 * 1024) // 256KB cache
                .with_sync_interval(Duration::from_secs(10))
                .with_wal(false), // Disable WAL for speed
            serialization: SerializationOptions::fastest(),
            debug: true,
        }
    }

    /// Create configuration optimized for production
    pub fn production<P: Into<PathBuf>>(data_dir: P) -> Self {
        Self {
            storage: StorageConfig::reliable(data_dir)
                .with_cache_size(4 * 1024 * 1024), // 4MB cache
            serialization: SerializationOptions::balanced(),
            debug: false,
        }
    }

    /// Set storage configuration
    pub fn with_storage(mut self, storage: StorageConfig) -> Self {
        self.storage = storage;
        self
    }

    /// Set serialization configuration
    pub fn with_serialization(mut self, serialization: SerializationOptions) -> Self {
        self.serialization = serialization;
        self
    }

    /// Enable or disable debug mode
    pub fn with_debug(mut self, debug: bool) -> Self {
        self.debug = debug;
        self
    }
}

impl Default for IndexerConfig {
    fn default() -> Self {
        Self::new("./indexer_data")
    }
}
