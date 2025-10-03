pub mod poseidon_hash;

pub use poseidon_hash::{internal, PoseidonHasher};

// Re-export the Hash type for convenience
pub type Hash = [u8; 32];
