use memmap2::{MmapMut, MmapOptions};
use parking_lot::{Mutex, RwLock};
use std::fs::{create_dir_all, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::Arc;

use crate::errors::{IndexerError, IndexerResult};
use crate::storage::{PageCache, StorageConfig, TreeMetadata, WalEntry, WriteAheadLog};
use crate::tree::{IncrementalMerkleTree, MerkleProof, DEFAULT_TREE_DEPTH};
use crate::utils::{hash_bytes, Hash};

// Storage constants
const LEAF_SIZE: usize = 32; // Hash size
const PAGE_SIZE: usize = 4096; // 4KB pages
const LEAVES_PER_PAGE: usize = PAGE_SIZE / (LEAF_SIZE + 1); // +1 for existence flag

/// Persistent Merkle tree with file-based storage
pub struct PersistentMerkleTree {
    config: StorageConfig,
    metadata: Arc<RwLock<TreeMetadata>>,

    // File handles
    data_file: Arc<Mutex<File>>,
    metadata_file: Arc<Mutex<File>>,
    wal: Option<WriteAheadLog>,

    // Memory-mapped region for hot data
    mmap: Option<Arc<Mutex<MmapMut>>>,

    // Cache for frequently accessed pages
    cache: Arc<Mutex<PageCache>>,

    // Zero hashes (computed once)
    zero_hashes: Vec<Hash>,

    // In-memory tree for root computation
    memory_tree: Arc<RwLock<IncrementalMerkleTree>>,
}

impl PersistentMerkleTree {
    /// Create or open a persistent Merkle tree
    pub fn new(config: StorageConfig) -> IndexerResult<Self> {
        // Create data directory
        create_dir_all(&config.data_dir)?;

        let data_path = config.data_dir.join("leaves.dat");
        let metadata_path = config.data_dir.join("metadata.dat");
        let wal_path = config.data_dir.join("wal.log");

        // Open or create files
        let data_file = Arc::new(Mutex::new(
            OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                .open(&data_path)?,
        ));

        let metadata_file = Arc::new(Mutex::new(
            OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                .open(&metadata_path)?,
        ));

        let wal = if config.enable_wal {
            let wal_file = OpenOptions::new()
                .create(true)
                .append(true)
                .read(true)
                .open(&wal_path)?;
            Some(WriteAheadLog::new(wal_file))
        } else {
            None
        };

        // Initialize zero hashes
        let zero_hashes = Self::compute_zero_hashes();

        // Load or create metadata
        let metadata = Self::load_or_create_metadata(&metadata_file, &zero_hashes)?;

        // Initialize cache
        let cache_pages = config.cache_size / PAGE_SIZE;
        let cache = Arc::new(Mutex::new(PageCache::new(cache_pages)));

        // Create in-memory tree for root computation
        let memory_tree = Arc::new(RwLock::new(IncrementalMerkleTree::new(20)));

        // Setup memory mapping for hot data
        let mmap = Self::setup_memory_mapping(&data_file)?;

        let mut tree = Self {
            config,
            metadata: Arc::new(RwLock::new(metadata)),
            data_file,
            metadata_file,
            wal,
            mmap,
            cache,
            zero_hashes,
            memory_tree,
        };

        // Load existing data
        tree.load_existing_data()?;

        Ok(tree)
    }

    /// Compute zero hashes for all levels
    fn compute_zero_hashes() -> Vec<Hash> {
        let mut zero_hashes = Vec::with_capacity(DEFAULT_TREE_DEPTH + 1);

        // Level 0: hash of single zero byte
        let base_zero = hash_bytes(&[0u8]);
        zero_hashes.push(base_zero);

        // Higher levels: zero_{i+1} = hash_pair(zero_i, zero_i)
        for i in 0..DEFAULT_TREE_DEPTH {
            let next = crate::utils::hash_pair(&zero_hashes[i], &zero_hashes[i]);
            zero_hashes.push(next);
        }

        zero_hashes
    }

    /// Load or create metadata
    fn load_or_create_metadata(
        metadata_file: &Arc<Mutex<File>>,
        zero_hashes: &[Hash],
    ) -> IndexerResult<TreeMetadata> {
        let mut file = metadata_file.lock();
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        if buffer.is_empty() {
            // Create new metadata
            let root_hash = zero_hashes[DEFAULT_TREE_DEPTH];
            Ok(TreeMetadata::new(DEFAULT_TREE_DEPTH, 0, root_hash))
        } else {
            // Load existing metadata
            let metadata: TreeMetadata = bincode::deserialize(&buffer)
                .map_err(|e| IndexerError::SerializationError(e.to_string()))?;
            metadata.verify_checksum()?;
            Ok(metadata)
        }
    }

    /// Setup memory mapping for hot data
    fn setup_memory_mapping(
        data_file: &Arc<Mutex<File>>,
    ) -> IndexerResult<Option<Arc<Mutex<MmapMut>>>> {
        let file = data_file.lock();

        // Ensure file has minimum size for memory mapping (1MB)
        let min_size = 1024 * 1024;
        let current_size = file.metadata()?.len();

        if current_size < min_size {
            file.set_len(min_size)?;
        }

        let mmap = unsafe {
            MmapOptions::new()
                .len(min_size as usize)
                .map_mut(&*file)
                .map_err(|e| IndexerError::StorageError(e.to_string()))?
        };

        Ok(Some(Arc::new(Mutex::new(mmap))))
    }

    /// Load existing data from disk
    fn load_existing_data(&mut self) -> IndexerResult<()> {
        let metadata = self.metadata.read();
        let next_index = metadata.next_index;
        drop(metadata);

        // Load existing leaves into memory tree
        let mut memory_tree = self.memory_tree.write();

        // Set the next index first
        memory_tree.set_next_index(next_index)?;

        // Load all existing leaf hashes
        for i in 0..next_index {
            if let Some(leaf_hash) = self.read_leaf_from_disk(i)? {
                memory_tree.set_leaf_hash(i, leaf_hash)?;
            }
        }

        drop(memory_tree);

        Ok(())
    }

    /// Append a new leaf to the tree
    pub fn append(&mut self, leaf_data: &[u8]) -> IndexerResult<usize> {
        let leaf_hash = hash_bytes(leaf_data);

        let mut metadata = self.metadata.write();
        if metadata.next_index >= (1 << DEFAULT_TREE_DEPTH) {
            return Err(IndexerError::TreeFull);
        }

        let index = metadata.next_index;

        // Write to WAL first if enabled
        if let Some(wal) = &self.wal {
            let entry = WalEntry::new(index, leaf_hash);
            wal.write_entry(&entry)?;
        }

        // Write to disk
        self.write_leaf_to_disk(index, &leaf_hash)?;

        // Update in-memory tree
        {
            let mut memory_tree = self.memory_tree.write();
            memory_tree.set_leaf_hash(index, leaf_hash)?;
            memory_tree.set_next_index(index + 1)?;
        }

        // Update metadata
        metadata.next_index = index + 1;
        metadata.root_hash = self.compute_root_hash();
        self.save_metadata(&metadata)?;

        Ok(index)
    }

    /// Update an existing leaf
    pub fn update(&mut self, index: usize, leaf_data: &[u8]) -> IndexerResult<()> {
        let metadata = self.metadata.read();
        if index >= metadata.next_index {
            return Err(IndexerError::IndexOutOfBounds);
        }
        drop(metadata);

        let leaf_hash = hash_bytes(leaf_data);

        // Write to WAL first if enabled
        if let Some(wal) = &self.wal {
            let entry = WalEntry::new(index, leaf_hash);
            wal.write_entry(&entry)?;
        }

        // Write to disk
        self.write_leaf_to_disk(index, &leaf_hash)?;

        // Update in-memory tree
        {
            let mut memory_tree = self.memory_tree.write();
            memory_tree.set_leaf_hash(index, leaf_hash)?;
        }

        // Update metadata
        let mut metadata = self.metadata.write();
        metadata.root_hash = self.compute_root_hash();
        self.save_metadata(&metadata)?;

        Ok(())
    }

    /// Write a leaf to disk
    fn write_leaf_to_disk(&self, index: usize, leaf_hash: &Hash) -> IndexerResult<()> {
        let page_id = index / LEAVES_PER_PAGE;
        let page_offset = index % LEAVES_PER_PAGE;

        // Try to use memory mapping for hot pages
        if let Some(mmap) = &self.mmap {
            let mmap_pages = (1024 * 1024) / PAGE_SIZE; // 1MB / 4KB
            if page_id < mmap_pages {
                let mut mmap = mmap.lock();
                let page_start = page_id * PAGE_SIZE;
                let leaf_start = page_start + page_offset * (LEAF_SIZE + 1);

                // Write existence flag and hash
                mmap[leaf_start] = 1;
                mmap[leaf_start + 1..leaf_start + 1 + LEAF_SIZE].copy_from_slice(leaf_hash);

                return Ok(());
            }
        }

        // Use regular file I/O with caching
        let mut cache = self.cache.lock();
        let page = if let Some(cached_page) = cache.get(page_id) {
            cached_page
        } else {
            let page_data = self.load_page_from_disk(page_id)?;
            cache.insert(page_id, page_data)
        };

        {
            let mut page_data = page.write();
            let leaf_start = page_offset * (LEAF_SIZE + 1);

            // Ensure page is large enough
            if page_data.len() < leaf_start + LEAF_SIZE + 1 {
                page_data.resize(PAGE_SIZE, 0);
            }

            // Write existence flag and hash
            page_data[leaf_start] = 1;
            page_data[leaf_start + 1..leaf_start + 1 + LEAF_SIZE].copy_from_slice(leaf_hash);
        }

        // Write page back to disk
        self.write_page_to_disk(page_id, &page)?;

        Ok(())
    }

    /// Read a leaf from disk
    fn read_leaf_from_disk(&self, index: usize) -> IndexerResult<Option<Hash>> {
        let page_id = index / LEAVES_PER_PAGE;
        let page_offset = index % LEAVES_PER_PAGE;

        // Try memory mapping first
        if let Some(mmap) = &self.mmap {
            let mmap_pages = (1024 * 1024) / PAGE_SIZE;
            if page_id < mmap_pages {
                let mmap = mmap.lock();
                let page_start = page_id * PAGE_SIZE;
                let leaf_start = page_start + page_offset * (LEAF_SIZE + 1);

                if leaf_start + LEAF_SIZE + 1 <= mmap.len() && mmap[leaf_start] == 1 {
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(&mmap[leaf_start + 1..leaf_start + 1 + LEAF_SIZE]);
                    return Ok(Some(hash));
                } else {
                    return Ok(None);
                }
            }
        }

        // Use cache
        let mut cache = self.cache.lock();
        let page = if let Some(cached_page) = cache.get(page_id) {
            cached_page
        } else {
            let page_data = self.load_page_from_disk(page_id)?;
            cache.insert(page_id, page_data)
        };

        let page_data = page.read();
        let leaf_start = page_offset * (LEAF_SIZE + 1);

        if leaf_start + LEAF_SIZE + 1 <= page_data.len() && page_data[leaf_start] == 1 {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&page_data[leaf_start + 1..leaf_start + 1 + LEAF_SIZE]);
            Ok(Some(hash))
        } else {
            Ok(None)
        }
    }

    /// Load a page from disk
    fn load_page_from_disk(&self, page_id: usize) -> IndexerResult<Vec<u8>> {
        let mut file = self.data_file.lock();
        let offset = page_id * PAGE_SIZE;

        file.seek(SeekFrom::Start(offset as u64))?;
        let mut buffer = vec![0u8; PAGE_SIZE];
        let bytes_read = file.read(&mut buffer)?;

        buffer.truncate(bytes_read);
        Ok(buffer)
    }

    /// Write a page to disk
    fn write_page_to_disk(&self, page_id: usize, page: &Arc<RwLock<Vec<u8>>>) -> IndexerResult<()> {
        let mut file = self.data_file.lock();
        let offset = page_id * PAGE_SIZE;

        file.seek(SeekFrom::Start(offset as u64))?;
        let page_data = page.read();
        file.write_all(&page_data)?;
        file.flush()?;

        Ok(())
    }

    /// Compute the current root hash
    fn compute_root_hash(&self) -> Hash {
        let memory_tree = self.memory_tree.read();
        memory_tree.root()
    }

    /// Save metadata to disk
    fn save_metadata(&self, metadata: &TreeMetadata) -> IndexerResult<()> {
        let mut updated_metadata = metadata.clone();
        updated_metadata.update_checksum();

        let mut file = self.metadata_file.lock();
        file.seek(SeekFrom::Start(0))?;
        file.set_len(0)?;

        let serialized = bincode::serialize(&updated_metadata)
            .map_err(|e| IndexerError::SerializationError(e.to_string()))?;
        file.write_all(&serialized)?;
        file.flush()?;

        Ok(())
    }

    /// Get current root hash
    pub fn root(&self) -> Hash {
        let metadata = self.metadata.read();
        metadata.root_hash
    }

    /// Get number of leaves
    pub fn len(&self) -> usize {
        let metadata = self.metadata.read();
        metadata.next_index
    }

    /// Check if tree is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get zero hash for a given level
    pub fn zero_hash(&self, level: usize) -> Option<Hash> {
        self.zero_hashes.get(level).copied()
    }

    /// Generate a Merkle proof for a leaf
    pub fn prove(&self, leaf_index: usize) -> IndexerResult<MerkleProof> {
        let memory_tree = self.memory_tree.read();
        memory_tree.prove(leaf_index)
    }

    /// Flush all pending writes to disk
    pub fn sync(&mut self) -> IndexerResult<()> {
        // Flush memory-mapped region
        if let Some(mmap) = &self.mmap {
            let mmap = mmap.lock();
            mmap.flush()
                .map_err(|e| IndexerError::StorageError(e.to_string()))?;
        }

        // Flush all cached pages
        let cache = self.cache.lock();
        for (page_id, page) in cache.pages() {
            self.write_page_to_disk(*page_id, page)?;
        }

        // Flush files
        {
            let mut file = self.data_file.lock();
            file.flush()?;
        }

        {
            let mut file = self.metadata_file.lock();
            file.flush()?;
        }

        // Truncate WAL after successful sync
        if let Some(wal) = &self.wal {
            wal.truncate()?;
        }

        Ok(())
    }
}

impl std::fmt::Debug for PersistentMerkleTree {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PersistentMerkleTree")
            .field("config", &self.config)
            .field("len", &self.len())
            .field("root", &hex::encode(self.root()))
            .finish()
    }
}
