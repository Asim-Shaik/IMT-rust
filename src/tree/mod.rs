pub mod commitment;
pub mod common;
pub mod incremental;
pub mod kv_trait;
pub mod proof;

pub const DEFAULT_TREE_DEPTH: usize = 20; // Default depth for the Merkle tree

pub use commitment::*;
pub use incremental::*;
pub use kv_trait::*;
pub use proof::*;
