use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::sync::Arc;

use crate::errors::{IndexerError, IndexerResult};
use crate::utils::Hash;

/// Write-ahead log entry
#[derive(Serialize, Deserialize, Debug)]
pub struct WalEntry {
    /// Timestamp when the entry was created
    pub timestamp: u64,
    /// Index of the leaf being modified
    pub index: usize,
    /// Hash of the leaf data
    pub hash: Hash,
}

impl WalEntry {
    /// Create a new WAL entry
    pub fn new(index: usize, hash: Hash) -> Self {
        Self {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            index,
            hash,
        }
    }
}

/// Write-ahead log for crash recovery
pub struct WriteAheadLog {
    file: Arc<Mutex<File>>,
}

impl WriteAheadLog {
    /// Create a new write-ahead log
    pub fn new(file: File) -> Self {
        Self {
            file: Arc::new(Mutex::new(file)),
        }
    }

    /// Write an entry to the log
    pub fn write_entry(&self, entry: &WalEntry) -> IndexerResult<()> {
        let mut file = self.file.lock();
        
        let serialized = bincode::serialize(entry)
            .map_err(|e| IndexerError::SerializationError(e.to_string()))?;
        
        // Write length prefix followed by the entry
        file.write_all(&(serialized.len() as u32).to_le_bytes())?;
        file.write_all(&serialized)?;
        file.flush()?;
        
        Ok(())
    }

    /// Truncate the log (called after successful sync)
    pub fn truncate(&self) -> IndexerResult<()> {
        let mut file = self.file.lock();
        file.seek(SeekFrom::Start(0))?;
        file.set_len(0)?;
        file.flush()?;
        Ok(())
    }

    /// Get a reference to the underlying file for recovery operations
    pub fn file(&self) -> Arc<Mutex<File>> {
        self.file.clone()
    }
}

impl std::fmt::Debug for WriteAheadLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WriteAheadLog").finish()
    }
}
