use crate::utils::{internal::hash_pair, Hash};

/// Merkle proof for a leaf in the tree
#[derive(Debug, Clone)]
pub struct MerkleProof {
    /// Index of the leaf this proof is for
    pub leaf_index: usize,
    /// Hash of the leaf
    pub leaf: Hash,
    /// Sibling hashes from leaf level up to root (excluding root)
    /// siblings[i] is the sibling at level i (0 = leaf level)
    pub siblings: Vec<Hash>,
}

impl MerkleProof {
    /// Create a new Merkle proof
    pub fn new(leaf_index: usize, leaf: Hash, siblings: Vec<Hash>) -> Self {
        Self {
            leaf_index,
            leaf,
            siblings,
        }
    }

    /// Verify this proof against a given root hash
    pub fn verify(&self, root: &Hash) -> bool {
        Self::verify_proof(&self.leaf, self.leaf_index, &self.siblings, root)
    }

    /// Static method to verify a proof without creating a MerkleProof instance
    pub fn verify_proof(leaf: &Hash, leaf_index: usize, siblings: &[Hash], root: &Hash) -> bool {
        let mut computed = *leaf;
        let mut idx = leaf_index;

        for sibling_hash in siblings.iter() {
            if idx % 2 == 0 {
                // Current node is left child
                computed = hash_pair(&computed, sibling_hash);
            } else {
                // Current node is right child
                computed = hash_pair(sibling_hash, &computed);
            }
            idx /= 2;
        }

        &computed == root
    }

    /// Get the depth of this proof (number of levels)
    pub fn depth(&self) -> usize {
        self.siblings.len()
    }
}
