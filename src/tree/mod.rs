pub mod commitment;
pub mod incremental;
pub mod proof;

pub const DEFAULT_TREE_DEPTH: usize = 20; // Default depth for the Merkle tree

pub use commitment::*;
pub use incremental::*;
pub use proof::*;
