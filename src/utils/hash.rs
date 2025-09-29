use sha2::{Digest, Sha256};

/// Hash type used throughout the system
pub type Hash = [u8; 32];

/// Hash arbitrary bytes using SHA-256
pub fn hash_bytes(input: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(input);
    let res = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&res);
    out
}

/// Hash a pair of hashes together with domain separation
pub fn hash_pair(a: &Hash, b: &Hash) -> Hash {
    // Domain separation: concatenate the two hashes
    let mut data = [0u8; 64];
    data[..32].copy_from_slice(a);
    data[32..].copy_from_slice(b);
    hash_bytes(&data)
}
