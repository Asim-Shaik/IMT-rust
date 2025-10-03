use crate::utils::Hash;
use solana_poseidon::{hashv, Endianness, Parameters, PoseidonSyscallError};

/// Poseidon hashing utilities for both sparse and incremental merkle trees
pub struct PoseidonHasher;

impl PoseidonHasher {
    /// Hash arbitrary bytes using Poseidon
    pub fn hash_bytes(input: &[u8]) -> Result<Hash, PoseidonSyscallError> {
        // For Poseidon, we need to ensure the input is within the field modulus
        // We'll truncate the input to fit within the field bounds
        let mut field_input = [0u8; 31]; // Use 31 bytes to ensure we're within field bounds
        let copy_len = std::cmp::min(input.len(), 31);
        field_input[..copy_len].copy_from_slice(&input[..copy_len]);

        // Add a domain separator to avoid collisions
        field_input[0] = field_input[0].wrapping_add(0x01);

        let result = hashv(Parameters::Bn254X5, Endianness::BigEndian, &[&field_input])?;

        Ok(result.to_bytes())
    }

    /// Hash a pair of hashes together using Poseidon
    pub fn hash_pair(a: &Hash, b: &Hash) -> Result<Hash, PoseidonSyscallError> {
        // For Poseidon, we need to ensure inputs are within the field modulus
        // We'll hash each 32-byte input separately and then combine them
        let hash_a = Self::hash_bytes(a)?;
        let hash_b = Self::hash_bytes(b)?;

        // Now combine the two hashed results
        let result = hashv(
            Parameters::Bn254X5,
            Endianness::BigEndian,
            &[&hash_a, &hash_b],
        )?;

        Ok(result.to_bytes())
    }

    /// Hash two arbitrary byte slices using Poseidon
    pub fn hash_two_slices(a: &[u8], b: &[u8]) -> Result<Hash, PoseidonSyscallError> {
        // Hash each slice separately first
        let hash_a = Self::hash_bytes(a)?;
        let hash_b = Self::hash_bytes(b)?;

        // Then combine the two hashed results
        let result = hashv(
            Parameters::Bn254X5,
            Endianness::BigEndian,
            &[&hash_a, &hash_b],
        )?;

        Ok(result.to_bytes())
    }

    /// Hash a single byte slice using Poseidon
    pub fn hash_slice(input: &[u8]) -> Result<Hash, PoseidonSyscallError> {
        Self::hash_bytes(input)
    }
}

/// Convenience functions that panic on error (for internal use)
pub mod internal {
    use super::*;

    /// Hash arbitrary bytes using Poseidon (panics on error)
    pub fn hash_bytes(input: &[u8]) -> Hash {
        PoseidonHasher::hash_bytes(input).expect("Poseidon hashing failed")
    }

    /// Hash a pair of hashes together using Poseidon (panics on error)
    pub fn hash_pair(a: &Hash, b: &Hash) -> Hash {
        PoseidonHasher::hash_pair(a, b).expect("Poseidon hashing failed")
    }

    /// Hash two arbitrary byte slices using Poseidon (panics on error)
    pub fn hash_two_slices(a: &[u8], b: &[u8]) -> Hash {
        PoseidonHasher::hash_two_slices(a, b).expect("Poseidon hashing failed")
    }

    /// Hash a single byte slice (padded to 32 bytes) using Poseidon (panics on error)
    pub fn hash_slice(input: &[u8]) -> Hash {
        PoseidonHasher::hash_slice(input).expect("Poseidon hashing failed")
    }
}
