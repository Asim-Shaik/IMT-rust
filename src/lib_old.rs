use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use memmap2::{MmapMut, MmapOptions};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{create_dir_all, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::Arc;

pub type Hash = [u8; 32];

// Fixed depth for the Merkle tree (based on the image requirements)
const TREE_DEPTH: usize = 20;

fn hash_bytes(input: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(input);
    let res = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&res);
    out
}

fn hash_pair(a: &Hash, b: &Hash) -> Hash {
    // Domain separation: prefix to avoid ambiguity
    let mut data = [0u8; 64];
    data[..32].copy_from_slice(a);
    data[32..].copy_from_slice(b);
    hash_bytes(&data)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Commitment {
    pub version: u32,
    pub commitment_index: u64,
    pub hash: Hash,
    pub random_secret: Hash,
    pub nullifier: Hash,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IncrementalMerkleTree {
    depth: usize,
    capacity: usize,
    // Leaves are optional; None means empty leaf (treated as zero-hash at level 0)
    leaves: Vec<Option<Hash>>,
    next_index: usize,
    zero_hashes: Vec<Hash>, // zero_hashes[level] where level 0 is leaf level
}

#[derive(Debug, Clone)]
pub struct MerkleProof {
    pub leaf_index: usize,
    pub leaf: Hash,
    // siblings[i] is sibling at level i (0 = leaf siblings) up to depth-1
    // (we do not include the root)
    pub siblings: Vec<Hash>,
}

impl IncrementalMerkleTree {
    /// Create a new tree with fixed depth.
    /// Capacity = 2^depth leaves.
    pub fn new() -> Self {
        let depth = TREE_DEPTH;
        let capacity = 1usize << depth;
        let mut zero_hashes = Vec::with_capacity(depth + 1);

        // base zero for leaves: hash of single zero byte (arbitrary but consistent)
        let base_zero = hash_bytes(&[0u8]);
        zero_hashes.push(base_zero);

        // compute zero for higher levels: zero_{i+1} = hash_pair(zero_i, zero_i)
        for i in 0..depth {
            let next = hash_pair(&zero_hashes[i], &zero_hashes[i]);
            zero_hashes.push(next);
        }

        Self {
            depth,
            capacity,
            leaves: vec![None; capacity],
            next_index: 0,
            zero_hashes,
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn len(&self) -> usize {
        self.next_index
    }

    pub fn is_full(&self) -> bool {
        self.next_index >= self.capacity
    }

    /// Append a leaf (as raw bytes). Returns Ok(index) or Err if full.
    pub fn append(&mut self, leaf_data: &[u8]) -> Result<usize, &'static str> {
        if self.is_full() {
            return Err("tree is full");
        }
        let leaf_hash = hash_bytes(leaf_data);
        let idx = self.next_index;
        self.leaves[idx] = Some(leaf_hash);
        self.next_index += 1;
        Ok(idx)
    }

    /// Update a leaf at index (must be < next_index) — optionally allow overwriting previously appended leaves.
    pub fn update(&mut self, index: usize, leaf_data: &[u8]) -> Result<(), &'static str> {
        if index >= self.next_index {
            return Err("index out of bounds (cannot update unappended leaf)");
        }
        let leaf_hash = hash_bytes(leaf_data);
        self.leaves[index] = Some(leaf_hash);
        Ok(())
    }

    /// Compute node hash at a given level and index.
    /// level = 0 => leaf level; level = depth => root level (index must be 0 at root).
    /// This function computes recursively from leaves, treating missing leaves as zero_hashes[0].
    fn node_hash_at(&self, level: usize, index: usize) -> Hash {
        if level == 0 {
            // leaf
            if index < self.capacity {
                if let Some(h) = self.leaves[index] {
                    return h;
                }
            }
            // missing leaf => zero leaf hash
            return self.zero_hashes[0];
        }
        // otherwise, compute children's indices at level-1
        let left = self.node_hash_at(level - 1, index * 2);
        let right = self.node_hash_at(level - 1, index * 2 + 1);
        hash_pair(&left, &right)
    }

    /// Return current root (hash at level `depth`, index 0)
    pub fn root(&self) -> Hash {
        self.node_hash_at(self.depth, 0)
    }

    /// Produce Merkle proof (siblings vector) for a given leaf index.
    /// Siblings are ordered from leaf level upward.
    pub fn prove(&self, leaf_index: usize) -> Result<MerkleProof, &'static str> {
        if leaf_index >= self.next_index {
            return Err("leaf_index not yet appended");
        }
        // leaf hash
        let leaf = match self.leaves[leaf_index] {
            Some(h) => h,
            None => self.zero_hashes[0], // shouldn't happen for appended index, but safe
        };

        let mut siblings: Vec<Hash> = Vec::with_capacity(self.depth);
        let mut idx = leaf_index;
        for level in 0..self.depth {
            let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            // sibling node at level `level` (node index sibling_idx)
            // we need to compute the node hash at level `level` for sibling_idx.
            let sibling_hash = if level == 0 {
                // leaf-level sibling: check capacity and appended status
                if sibling_idx < self.capacity {
                    if let Some(h) = self.leaves[sibling_idx] {
                        h
                    } else {
                        self.zero_hashes[0]
                    }
                } else {
                    self.zero_hashes[0]
                }
            } else {
                // internal sibling: compute via node_hash_at(level, sibling_idx)
                // but be careful: sibling_idx might exceed node count at that level.
                // max index at level `level` is (2^(depth-level)) - 1
                let max_idx_at_level = (1usize << (self.depth - level)) - 1;
                if sibling_idx <= max_idx_at_level {
                    self.node_hash_at(level, sibling_idx)
                } else {
                    // out-of-range => zero for that level
                    self.zero_hashes[level]
                }
            };
            siblings.push(sibling_hash);
            idx /= 2; // move to parent index for next level
        }

        Ok(MerkleProof {
            leaf_index,
            leaf,
            siblings,
        })
    }

    /// Verify a proof against root for this tree depth.
    pub fn verify_proof(leaf: &Hash, leaf_index: usize, siblings: &[Hash], root: &Hash) -> bool {
        let mut computed = *leaf;
        let mut idx = leaf_index;
        for sibling_hash in siblings.iter() {
            if idx % 2 == 0 {
                // current is left
                computed = hash_pair(&computed, sibling_hash);
            } else {
                // current is right
                computed = hash_pair(sibling_hash, &computed);
            }
            idx /= 2;
        }
        &computed == root
    }
}

/// Parse a new commitment from raw data
/// Based on the image, this should parse version, commitment_index, hash, random_secret, nullifier
pub fn parse_new_commitment(data: &[u8]) -> Result<Commitment, &'static str> {
    if data.len() < 4 + 8 + 32 + 32 + 32 {
        return Err("insufficient data for commitment");
    }

    let mut offset = 0;

    // Parse version (4 bytes)
    let version = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    offset += 4;

    // Parse commitment_index (8 bytes)
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

    Ok(Commitment {
        version,
        commitment_index,
        hash,
        random_secret,
        nullifier,
    })
}

/// Insert a commitment into the incremental Merkle tree
pub fn insert_into_incremental_merkle_tree(
    tree: &mut IncrementalMerkleTree,
    commitment: &Commitment,
) -> Result<usize, &'static str> {
    // Serialize the commitment for insertion
    let commitment_data =
        bincode::serialize(commitment).map_err(|_| "failed to serialize commitment")?;

    tree.append(&commitment_data)
}

/// Get the Merkle path (proof) for a commitment at a specific index
pub fn get_merkle_path_for_commitment(
    tree: &IncrementalMerkleTree,
    commitment_index: usize,
) -> Result<MerkleProof, &'static str> {
    tree.prove(commitment_index)
}

/// Persist the incremental Merkle tree fully (serialize to bytes)
pub fn persist_incremental_merkle_tree_fully(
    tree: &IncrementalMerkleTree,
) -> Result<Vec<u8>, &'static str> {
    bincode::serialize(tree).map_err(|_| "failed to serialize tree")
}

/// Persist the incremental Merkle tree (lighter version - just the essential data)
pub fn persist_incremental_merkle_tree(
    tree: &IncrementalMerkleTree,
) -> Result<Vec<u8>, &'static str> {
    // For the lighter version, we could serialize just the leaves and next_index
    // and reconstruct zero_hashes on deserialization
    #[derive(Serialize)]
    struct LightTree {
        next_index: usize,
        leaves: Vec<Option<Hash>>,
    }

    let light_tree = LightTree {
        next_index: tree.next_index,
        leaves: tree.leaves.clone(),
    };

    bincode::serialize(&light_tree).map_err(|_| "failed to serialize light tree")
}

#[derive(Debug, Clone)]
pub enum SerializationFormat {
    Bincode,
    MessagePack,
    Postcard,
}

#[derive(Debug, Clone)]
pub struct SerializationOptions {
    pub format: SerializationFormat,
    pub compress: bool,
    pub compression_level: u32,
}

impl Default for SerializationOptions {
    fn default() -> Self {
        Self {
            format: SerializationFormat::Bincode,
            compress: true,
            compression_level: 6,
        }
    }
}

/// Optimized serialization that only stores non-empty leaves in a compact format
#[derive(Serialize, Deserialize)]
struct CompactTree {
    next_index: usize,
    // Store only non-empty leaves as (index, hash) pairs
    non_empty_leaves: Vec<(usize, Hash)>,
}

impl From<&IncrementalMerkleTree> for CompactTree {
    fn from(tree: &IncrementalMerkleTree) -> Self {
        let non_empty_leaves: Vec<(usize, Hash)> = tree
            .leaves
            .iter()
            .enumerate()
            .take(tree.next_index)
            .filter_map(|(i, leaf)| leaf.map(|hash| (i, hash)))
            .collect();

        CompactTree {
            next_index: tree.next_index,
            non_empty_leaves,
        }
    }
}

impl CompactTree {
    fn to_tree(&self) -> IncrementalMerkleTree {
        let mut tree = IncrementalMerkleTree::new();
        tree.next_index = self.next_index;

        // Restore non-empty leaves
        for (index, hash) in &self.non_empty_leaves {
            if *index < tree.capacity {
                tree.leaves[*index] = Some(*hash);
            }
        }

        tree
    }
}

/// Most optimized serialization - stores only the essential data in the most compact way
pub fn serialize_tree_optimized(
    tree: &IncrementalMerkleTree,
    options: &SerializationOptions,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let compact_tree = CompactTree::from(tree);

    let serialized = match options.format {
        SerializationFormat::Bincode => bincode::serialize(&compact_tree)?,
        SerializationFormat::MessagePack => rmp_serde::to_vec(&compact_tree)?,
        SerializationFormat::Postcard => {
            let mut buffer = [0u8; 65536]; // 64KB buffer should be enough for most trees
            let slice = postcard::to_slice(&compact_tree, &mut buffer)?;
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

/// Deserialize optimized tree format
pub fn deserialize_tree_optimized(
    data: &[u8],
    options: &SerializationOptions,
) -> Result<IncrementalMerkleTree, Box<dyn std::error::Error>> {
    let decompressed = if options.compress {
        let mut decoder = GzDecoder::new(data);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed)?;
        decompressed
    } else {
        data.to_vec()
    };

    let compact_tree: CompactTree = match options.format {
        SerializationFormat::Bincode => bincode::deserialize(&decompressed)?,
        SerializationFormat::MessagePack => rmp_serde::from_slice(&decompressed)?,
        SerializationFormat::Postcard => postcard::from_bytes(&decompressed)?,
    };

    Ok(compact_tree.to_tree())
}

/// Delta serialization for incremental updates
#[derive(Serialize, Deserialize)]
pub struct TreeDelta {
    pub base_next_index: usize,
    pub new_leaves: Vec<(usize, Hash)>,
    pub updated_leaves: Vec<(usize, Hash)>,
}

impl IncrementalMerkleTree {
    /// Create a delta from this tree to another tree (for incremental serialization)
    pub fn create_delta(&self, other: &IncrementalMerkleTree) -> TreeDelta {
        let mut new_leaves = Vec::new();
        let mut updated_leaves = Vec::new();

        // Find new leaves (beyond the original next_index)
        for i in self.next_index..other.next_index {
            if let Some(hash) = other.leaves[i] {
                new_leaves.push((i, hash));
            }
        }

        // Find updated leaves (within the original range)
        for i in 0..self.next_index.min(other.next_index) {
            if self.leaves[i] != other.leaves[i] {
                if let Some(hash) = other.leaves[i] {
                    updated_leaves.push((i, hash));
                }
            }
        }

        TreeDelta {
            base_next_index: self.next_index,
            new_leaves,
            updated_leaves,
        }
    }

    /// Apply a delta to this tree
    pub fn apply_delta(&mut self, delta: &TreeDelta) -> Result<(), &'static str> {
        // Apply updated leaves
        for (index, hash) in &delta.updated_leaves {
            if *index >= self.capacity {
                return Err("delta index out of bounds");
            }
            self.leaves[*index] = Some(*hash);
        }

        // Apply new leaves
        for (index, hash) in &delta.new_leaves {
            if *index >= self.capacity {
                return Err("delta index out of bounds");
            }
            self.leaves[*index] = Some(*hash);
            if *index >= self.next_index {
                self.next_index = *index + 1;
            }
        }

        Ok(())
    }
}

/// Serialize only a delta/diff between trees
pub fn serialize_tree_delta(
    delta: &TreeDelta,
    options: &SerializationOptions,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let serialized = match options.format {
        SerializationFormat::Bincode => bincode::serialize(delta)?,
        SerializationFormat::MessagePack => rmp_serde::to_vec(delta)?,
        SerializationFormat::Postcard => {
            let mut buffer = [0u8; 65536]; // 64KB buffer should be enough for deltas
            let slice = postcard::to_slice(delta, &mut buffer)?;
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

/// Deserialize tree delta
pub fn deserialize_tree_delta(
    data: &[u8],
    options: &SerializationOptions,
) -> Result<TreeDelta, Box<dyn std::error::Error>> {
    let decompressed = if options.compress {
        let mut decoder = GzDecoder::new(data);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed)?;
        decompressed
    } else {
        data.to_vec()
    };

    let delta = match options.format {
        SerializationFormat::Bincode => bincode::deserialize(&decompressed)?,
        SerializationFormat::MessagePack => rmp_serde::from_slice(&decompressed)?,
        SerializationFormat::Postcard => postcard::from_bytes(&decompressed)?,
    };

    Ok(delta)
}

// File-based storage constants
const LEAF_SIZE: usize = 32; // Hash size
const PAGE_SIZE: usize = 4096; // 4KB pages
const LEAVES_PER_PAGE: usize = PAGE_SIZE / (LEAF_SIZE + 1); // +1 for existence flag
                                                            // const METADATA_SIZE: usize = 64; // Metadata header size (reserved for future use)

#[derive(Debug, Clone)]
pub struct StorageConfig {
    pub data_dir: PathBuf,
    pub cache_size: usize,
    pub sync_interval: std::time::Duration,
    pub compression: bool,
    pub enable_wal: bool, // Write-Ahead Logging
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("./merkle_data"),
            cache_size: 1024 * 1024, // 1MB cache
            sync_interval: std::time::Duration::from_secs(5),
            compression: true,
            enable_wal: true,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct TreeMetadata {
    version: u32,
    depth: usize,
    next_index: usize,
    root_hash: Hash,
    last_sync: u64,
    checksum: u32,
}

impl TreeMetadata {
    fn new(depth: usize, next_index: usize, root_hash: Hash) -> Self {
        let mut metadata = Self {
            version: 1,
            depth,
            next_index,
            root_hash,
            last_sync: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            checksum: 0,
        };

        // Calculate checksum
        let serialized = bincode::serialize(&(
            metadata.version,
            metadata.depth,
            metadata.next_index,
            metadata.root_hash,
            metadata.last_sync,
        ))
        .unwrap();
        metadata.checksum = crc32fast::hash(&serialized);

        metadata
    }

    fn verify_checksum(&self) -> bool {
        let serialized = bincode::serialize(&(
            self.version,
            self.depth,
            self.next_index,
            self.root_hash,
            self.last_sync,
        ))
        .unwrap();
        let calculated_checksum = crc32fast::hash(&serialized);
        calculated_checksum == self.checksum
    }
}

#[derive(Debug)]
struct PageCache {
    pages: HashMap<usize, Arc<RwLock<Vec<u8>>>>,
    max_size: usize,
    access_order: Vec<usize>,
}

impl PageCache {
    fn new(max_size: usize) -> Self {
        Self {
            pages: HashMap::new(),
            max_size,
            access_order: Vec::new(),
        }
    }

    fn get(&mut self, page_id: usize) -> Option<Arc<RwLock<Vec<u8>>>> {
        if let Some(page) = self.pages.get(&page_id) {
            // Move to end (most recently used)
            self.access_order.retain(|&id| id != page_id);
            self.access_order.push(page_id);
            Some(page.clone())
        } else {
            None
        }
    }

    fn insert(&mut self, page_id: usize, page_data: Vec<u8>) -> Arc<RwLock<Vec<u8>>> {
        // Evict if necessary
        while self.pages.len() >= self.max_size && !self.access_order.is_empty() {
            let lru_page = self.access_order.remove(0);
            self.pages.remove(&lru_page);
        }

        let page = Arc::new(RwLock::new(page_data));
        self.pages.insert(page_id, page.clone());
        self.access_order.push(page_id);
        page
    }
}

#[derive(Debug)]
pub struct PersistentMerkleTree {
    config: StorageConfig,
    metadata: Arc<RwLock<TreeMetadata>>,

    // File handles
    data_file: Arc<Mutex<File>>,
    metadata_file: Arc<Mutex<File>>,
    wal_file: Option<Arc<Mutex<File>>>,

    // Memory-mapped region for hot data
    mmap: Option<Arc<Mutex<MmapMut>>>,

    // Cache for frequently accessed pages
    cache: Arc<Mutex<PageCache>>,

    // Zero hashes (computed once)
    zero_hashes: Vec<Hash>,

    // In-memory tree for comparison (can be removed in production)
    memory_tree: Arc<RwLock<IncrementalMerkleTree>>,
}

impl PersistentMerkleTree {
    /// Create or open a persistent Merkle tree
    pub fn new(config: StorageConfig) -> Result<Self, Box<dyn std::error::Error>> {
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

        let wal_file = if config.enable_wal {
            Some(Arc::new(Mutex::new(
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .read(true)
                    .open(&wal_path)?,
            )))
        } else {
            None
        };

        // Initialize zero hashes
        let mut zero_hashes = Vec::with_capacity(TREE_DEPTH + 1);
        let base_zero = hash_bytes(&[0u8]);
        zero_hashes.push(base_zero);

        for i in 0..TREE_DEPTH {
            let next = hash_pair(&zero_hashes[i], &zero_hashes[i]);
            zero_hashes.push(next);
        }

        // Load or create metadata
        let metadata = Self::load_or_create_metadata(&metadata_file, &zero_hashes)?;

        // Initialize cache
        let cache_pages = config.cache_size / PAGE_SIZE;
        let cache = Arc::new(Mutex::new(PageCache::new(cache_pages)));

        // Create in-memory tree for comparison
        let memory_tree = Arc::new(RwLock::new(IncrementalMerkleTree::new()));

        // Setup memory mapping for hot data (first few pages)
        let mmap = Self::setup_memory_mapping(&data_file)?;

        let mut tree = Self {
            config,
            metadata: Arc::new(RwLock::new(metadata)),
            data_file,
            metadata_file,
            wal_file,
            mmap,
            cache,
            zero_hashes,
            memory_tree,
        };

        // Load existing data if any
        tree.load_existing_data()?;

        Ok(tree)
    }

    fn load_or_create_metadata(
        metadata_file: &Arc<Mutex<File>>,
        zero_hashes: &[Hash],
    ) -> Result<TreeMetadata, Box<dyn std::error::Error>> {
        let mut file = metadata_file.lock();
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        if buffer.is_empty() {
            // Create new metadata
            let root_hash = zero_hashes[TREE_DEPTH];
            Ok(TreeMetadata::new(TREE_DEPTH, 0, root_hash))
        } else {
            // Load existing metadata
            let metadata: TreeMetadata = bincode::deserialize(&buffer)?;
            if !metadata.verify_checksum() {
                return Err("Metadata checksum verification failed".into());
            }
            Ok(metadata)
        }
    }

    fn setup_memory_mapping(
        data_file: &Arc<Mutex<File>>,
    ) -> Result<Option<Arc<Mutex<MmapMut>>>, Box<dyn std::error::Error>> {
        #[allow(unused_mut)]
        let mut file = data_file.lock();

        // Ensure file has minimum size for memory mapping (1MB)
        let min_size = 1024 * 1024;
        let current_size = file.metadata()?.len();

        if current_size < min_size {
            file.set_len(min_size)?;
        }

        let mmap = unsafe { MmapOptions::new().len(min_size as usize).map_mut(&*file)? };

        Ok(Some(Arc::new(Mutex::new(mmap))))
    }

    fn load_existing_data(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let metadata = self.metadata.read();
        let next_index = metadata.next_index;
        drop(metadata);

        // Load existing leaves into memory tree for comparison
        let mut memory_tree = self.memory_tree.write();

        for i in 0..next_index {
            if let Some(leaf_hash) = self.read_leaf_from_disk(i)? {
                // Find corresponding data that produces this hash
                // For now, we'll store the hash directly
                memory_tree.leaves[i] = Some(leaf_hash);
            }
        }

        memory_tree.next_index = next_index;
        drop(memory_tree);

        Ok(())
    }

    /// Append a new leaf to the tree
    pub fn append(&mut self, leaf_data: &[u8]) -> Result<usize, Box<dyn std::error::Error>> {
        let leaf_hash = hash_bytes(leaf_data);

        let mut metadata = self.metadata.write();
        if metadata.next_index >= (1 << TREE_DEPTH) {
            return Err("Tree is full".into());
        }

        let index = metadata.next_index;

        // Write to WAL first if enabled
        if let Some(wal_file) = &self.wal_file {
            self.write_wal_entry(index, &leaf_hash, wal_file)?;
        }

        // Write to disk
        self.write_leaf_to_disk(index, &leaf_hash)?;

        // Update in-memory tree
        {
            let mut memory_tree = self.memory_tree.write();
            memory_tree.leaves[index] = Some(leaf_hash);
            memory_tree.next_index = index + 1;
        }

        // Update metadata
        metadata.next_index = index + 1;
        metadata.root_hash = self.compute_root_hash();

        // Save metadata
        self.save_metadata(&metadata)?;

        drop(metadata);

        Ok(index)
    }

    /// Update an existing leaf
    pub fn update(
        &mut self,
        index: usize,
        leaf_data: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let metadata = self.metadata.read();
        if index >= metadata.next_index {
            return Err("Index out of bounds".into());
        }
        drop(metadata);

        let leaf_hash = hash_bytes(leaf_data);

        // Write to WAL first if enabled
        if let Some(wal_file) = &self.wal_file {
            self.write_wal_entry(index, &leaf_hash, wal_file)?;
        }

        // Write to disk
        self.write_leaf_to_disk(index, &leaf_hash)?;

        // Update in-memory tree
        {
            let mut memory_tree = self.memory_tree.write();
            memory_tree.leaves[index] = Some(leaf_hash);
        }

        // Update metadata
        let mut metadata = self.metadata.write();
        metadata.root_hash = self.compute_root_hash();
        self.save_metadata(&metadata)?;

        Ok(())
    }

    fn write_wal_entry(
        &self,
        index: usize,
        leaf_hash: &Hash,
        wal_file: &Arc<Mutex<File>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        #[derive(Serialize)]
        struct WalEntry {
            timestamp: u64,
            index: usize,
            hash: Hash,
        }

        let entry = WalEntry {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_millis() as u64,
            index,
            hash: *leaf_hash,
        };

        let mut file = wal_file.lock();
        let serialized = bincode::serialize(&entry)?;
        file.write_all(&(serialized.len() as u32).to_le_bytes())?;
        file.write_all(&serialized)?;
        file.flush()?;

        Ok(())
    }

    fn write_leaf_to_disk(
        &self,
        index: usize,
        leaf_hash: &Hash,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let page_id = index / LEAVES_PER_PAGE;
        let page_offset = index % LEAVES_PER_PAGE;

        // Try to use memory mapping for hot pages (first few pages)
        if let Some(mmap) = &self.mmap {
            let mmap_pages = (1024 * 1024) / PAGE_SIZE; // 1MB / 4KB
            if page_id < mmap_pages {
                let mut mmap = mmap.lock();
                let page_start = page_id * PAGE_SIZE;
                let leaf_start = page_start + page_offset * (LEAF_SIZE + 1);

                // Write existence flag
                mmap[leaf_start] = 1;
                // Write hash
                mmap[leaf_start + 1..leaf_start + 1 + LEAF_SIZE].copy_from_slice(leaf_hash);

                return Ok(());
            }
        }

        // Use regular file I/O with caching
        let mut cache = self.cache.lock();
        let page = if let Some(cached_page) = cache.get(page_id) {
            cached_page
        } else {
            // Load page from disk
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

    fn read_leaf_from_disk(
        &self,
        index: usize,
    ) -> Result<Option<Hash>, Box<dyn std::error::Error>> {
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

    fn load_page_from_disk(&self, page_id: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut file = self.data_file.lock();
        let offset = page_id * PAGE_SIZE;

        file.seek(SeekFrom::Start(offset as u64))?;
        let mut buffer = vec![0u8; PAGE_SIZE];
        let bytes_read = file.read(&mut buffer)?;

        buffer.truncate(bytes_read);
        Ok(buffer)
    }

    fn write_page_to_disk(
        &self,
        page_id: usize,
        page: &Arc<RwLock<Vec<u8>>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut file = self.data_file.lock();
        let offset = page_id * PAGE_SIZE;

        file.seek(SeekFrom::Start(offset as u64))?;
        let page_data = page.read();
        file.write_all(&page_data)?;
        file.flush()?;

        Ok(())
    }

    fn compute_root_hash(&self) -> Hash {
        let memory_tree = self.memory_tree.read();
        memory_tree.root()
    }

    fn save_metadata(&self, metadata: &TreeMetadata) -> Result<(), Box<dyn std::error::Error>> {
        // Create a new metadata with updated checksum
        let mut updated_metadata = metadata.clone();
        updated_metadata.last_sync = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Recalculate checksum
        let serialized_for_checksum = bincode::serialize(&(
            updated_metadata.version,
            updated_metadata.depth,
            updated_metadata.next_index,
            updated_metadata.root_hash,
            updated_metadata.last_sync,
        ))?;
        updated_metadata.checksum = crc32fast::hash(&serialized_for_checksum);

        let mut file = self.metadata_file.lock();
        file.seek(SeekFrom::Start(0))?;
        file.set_len(0)?; // Truncate file

        let serialized = bincode::serialize(&updated_metadata)?;
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

    /// Get the zero hash for a given level (used for empty subtrees)
    pub fn zero_hash(&self, level: usize) -> Option<Hash> {
        self.zero_hashes.get(level).copied()
    }

    /// Generate a Merkle proof for a leaf
    pub fn prove(&self, leaf_index: usize) -> Result<MerkleProof, Box<dyn std::error::Error>> {
        let memory_tree = self.memory_tree.read();
        match memory_tree.prove(leaf_index) {
            Ok(proof) => Ok(proof),
            Err(e) => Err(e.into()),
        }
    }

    /// Flush all pending writes to disk
    pub fn sync(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Flush memory-mapped region
        if let Some(mmap) = &self.mmap {
            let mmap = mmap.lock();
            mmap.flush()?;
        }

        // Flush all cached pages
        let cache = self.cache.lock();
        for (page_id, page) in &cache.pages {
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

        if let Some(wal_file) = &self.wal_file {
            let mut file = wal_file.lock();
            file.flush()?;
        }

        Ok(())
    }

    /// Compact the data files (remove fragmentation)
    pub fn compact(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Create temporary file
        let temp_path = self.config.data_dir.join("leaves.dat.tmp");
        let mut temp_file = File::create(&temp_path)?;

        let metadata = self.metadata.read();
        let next_index = metadata.next_index;
        drop(metadata);

        // Copy only active leaves to new file
        let mut new_page_buffer = vec![0u8; PAGE_SIZE];
        let mut current_page = 0;
        let mut page_offset = 0;

        for i in 0..next_index {
            if let Some(leaf_hash) = self.read_leaf_from_disk(i)? {
                let leaf_start = page_offset * (LEAF_SIZE + 1);

                // Check if we need a new page
                if leaf_start + LEAF_SIZE + 1 > PAGE_SIZE {
                    // Write current page
                    temp_file.seek(SeekFrom::Start((current_page * PAGE_SIZE) as u64))?;
                    temp_file.write_all(&new_page_buffer)?;

                    // Start new page
                    current_page += 1;
                    page_offset = 0;
                    new_page_buffer.fill(0);
                }

                let leaf_start = page_offset * (LEAF_SIZE + 1);
                new_page_buffer[leaf_start] = 1;
                new_page_buffer[leaf_start + 1..leaf_start + 1 + LEAF_SIZE]
                    .copy_from_slice(&leaf_hash);
                page_offset += 1;
            }
        }

        // Write final page
        if page_offset > 0 {
            temp_file.seek(SeekFrom::Start((current_page * PAGE_SIZE) as u64))?;
            temp_file.write_all(&new_page_buffer)?;
        }

        temp_file.flush()?;
        drop(temp_file);

        // Replace old file with new one
        std::fs::rename(&temp_path, self.config.data_dir.join("leaves.dat"))?;

        // Clear cache as file layout changed
        {
            let mut cache = self.cache.lock();
            cache.pages.clear();
            cache.access_order.clear();
        }

        // Recreate memory mapping
        self.mmap = Self::setup_memory_mapping(&self.data_file)?;

        Ok(())
    }
}
