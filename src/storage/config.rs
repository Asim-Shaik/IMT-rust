use std::path::PathBuf;
use std::time::Duration;

/// Configuration for persistent storage
#[derive(Debug, Clone)]
pub struct StorageConfig {
    /// Directory where data files are stored
    pub data_dir: PathBuf,
    /// Size of the page cache in bytes
    pub cache_size: usize,
    /// How often to sync data to disk
    pub sync_interval: Duration,
    /// Whether to enable compression
    pub compression: bool,
    /// Whether to enable write-ahead logging
    pub enable_wal: bool,
}

impl StorageConfig {
    /// Create a new storage configuration
    pub fn new<P: Into<PathBuf>>(data_dir: P) -> Self {
        Self {
            data_dir: data_dir.into(),
            cache_size: 1024 * 1024, // 1MB default
            sync_interval: Duration::from_secs(5),
            compression: true,
            enable_wal: true,
        }
    }

    /// Set the cache size in bytes
    pub fn with_cache_size(mut self, cache_size: usize) -> Self {
        self.cache_size = cache_size;
        self
    }

    /// Set the sync interval
    pub fn with_sync_interval(mut self, interval: Duration) -> Self {
        self.sync_interval = interval;
        self
    }

    /// Enable or disable compression
    pub fn with_compression(mut self, enable: bool) -> Self {
        self.compression = enable;
        self
    }

    /// Enable or disable write-ahead logging
    pub fn with_wal(mut self, enable: bool) -> Self {
        self.enable_wal = enable;
        self
    }

    /// Create configuration optimized for speed
    pub fn fast<P: Into<PathBuf>>(data_dir: P) -> Self {
        Self {
            data_dir: data_dir.into(),
            cache_size: 4 * 1024 * 1024, // 4MB cache
            sync_interval: Duration::from_secs(10),
            compression: false,
            enable_wal: false,
        }
    }

    /// Create configuration optimized for reliability
    pub fn reliable<P: Into<PathBuf>>(data_dir: P) -> Self {
        Self {
            data_dir: data_dir.into(),
            cache_size: 1024 * 1024, // 1MB cache
            sync_interval: Duration::from_secs(1),
            compression: true,
            enable_wal: true,
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self::new("./merkle_data")
    }
}
