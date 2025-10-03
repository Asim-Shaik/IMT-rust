use std::cell::RefCell;
use std::rc::Rc;

use crate::errors::IndexerResult;
use crate::tree::common::*;
use crate::tree::kv_trait::AuthenticatedKV;
use crate::tree::Commitment;
use bincode;
use bitvec::prelude::*;
use hex;
use serde::{Deserialize, Serialize};

/// Default depth for sparse merkle tree (Poseidon = 32 bytes)
const DEFAULT_KEY_BITS: usize = crate::tree::DEFAULT_TREE_DEPTH;

/// Default value used for non-existent keys in proofs
const DEFAULT_VALUE_FOR_MISSING: &str = "";

/// Serializable representation of a node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SerializableNode {
    Empty,
    Leaf {
        key: String,
        value: String,
    },
    Branch {
        left: Box<SerializableNode>,
        right: Box<SerializableNode>,
        hash: [u8; 32],
    },
}

impl SerializableNode {
    /// Convert to runtime Node
    pub fn to_node(&self) -> Node {
        match self {
            SerializableNode::Empty => Node::Empty,
            SerializableNode::Leaf { key, value } => Node::Leaf(Leaf {
                key: key.clone(),
                value: value.clone(),
            }),
            SerializableNode::Branch { left, right, hash } => {
                let left_wrapper = NodeWrapper::new(left.to_node());
                let right_wrapper = NodeWrapper::new(right.to_node());
                Node::Branch(Branch {
                    left: left_wrapper,
                    right: right_wrapper,
                    hash: *hash,
                })
            }
        }
    }

    /// Convert from runtime Node
    pub fn from_node(node: &Node) -> Self {
        match node {
            Node::Empty => SerializableNode::Empty,
            Node::Leaf(leaf) => SerializableNode::Leaf {
                key: leaf.key.clone(),
                value: leaf.value.clone(),
            },
            Node::Branch(branch) => SerializableNode::Branch {
                left: Box::new(SerializableNode::from_node(&branch.left.borrow())),
                right: Box::new(SerializableNode::from_node(&branch.right.borrow())),
                hash: branch.hash,
            },
        }
    }

    /// Get the hash of this node
    pub fn get_hash(&self) -> Digest {
        match self {
            SerializableNode::Empty => zero_digest(),
            SerializableNode::Leaf { key, value } => smt_utils::hash_kv(key, value),
            SerializableNode::Branch { hash, .. } => {
                let mut digest = zero_digest();
                digest.as_mut().copy_from_slice(hash);
                digest
            }
        }
    }
}

/// Serializable representation of the sparse merkle tree
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableSparseTree {
    pub root: SerializableNode,
}

/// Wrapper for runtime node operations
#[derive(Debug, Clone)]
pub struct NodeWrapper(Rc<RefCell<Node>>);

impl Default for NodeWrapper {
    fn default() -> Self {
        Self::new(Node::Empty)
    }
}

impl NodeWrapper {
    pub fn new(node: Node) -> Self {
        Self(Rc::new(RefCell::new(node)))
    }

    pub fn borrow(&self) -> std::cell::Ref<Node> {
        self.0.borrow()
    }

    pub fn borrow_mut(&self) -> std::cell::RefMut<Node> {
        self.0.borrow_mut()
    }
}

impl From<Rc<RefCell<Node>>> for NodeWrapper {
    fn from(rc: Rc<RefCell<Node>>) -> Self {
        Self(rc)
    }
}

impl From<NodeWrapper> for Rc<RefCell<Node>> {
    fn from(wrapper: NodeWrapper) -> Self {
        wrapper.0
    }
}

// Removed Deref impl - use explicit borrow()/borrow_mut() methods instead

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SparseMerkleTree {
    /// The serializable part of the tree
    pub serializable: SerializableSparseTree,
    /// Current root digest (computed from serializable tree)
    pub root_digest: Digest,
    /// Tree depth (configurable)
    pub depth: usize,
}

impl Default for SparseMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl SparseMerkleTree {
    pub fn new() -> Self {
        Self::with_depth(DEFAULT_KEY_BITS)
    }

    /// Create a new sparse merkle tree with specified depth
    pub fn with_depth(depth: usize) -> Self {
        let serializable = SerializableSparseTree {
            root: SerializableNode::Empty,
        };
        let root_digest = serializable.root.get_hash();
        SparseMerkleTree {
            serializable,
            root_digest,
            depth,
        }
    }

    /// Create from serializable tree with specified depth
    pub fn from_serializable(serializable: SerializableSparseTree, depth: usize) -> Self {
        let root_digest = serializable.root.get_hash();
        SparseMerkleTree {
            serializable,
            root_digest,
            depth,
        }
    }

    /// Get the tree depth
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// Insert a commitment into the tree
    pub fn insert_commitment(&mut self, commitment: &Commitment) -> IndexerResult<()> {
        let commitment_data = bincode::serialize(commitment)?;
        let commitment_key = format!("commitment_{}", commitment.commitment_index);
        let commitment_value = hex::encode(&commitment_data);

        // Insert as key-value pair
        *self = self.clone().insert(commitment_key, commitment_value);
        Ok(())
    }

    /// Get a commitment by index
    pub fn get_commitment(&self, commitment_index: u64) -> IndexerResult<Option<Commitment>> {
        let commitment_key = format!("commitment_{}", commitment_index);
        let (value, _) = self.get(commitment_key);

        match value {
            Some(hex_data) => {
                let data = hex::decode(hex_data)?;
                let commitment = Commitment::from_bytes(&data)?;
                Ok(Some(commitment))
            }
            None => Ok(None),
        }
    }

    /// Get all commitments in the tree
    pub fn get_all_commitments(&self) -> IndexerResult<Vec<Commitment>> {
        let mut commitments = Vec::new();

        // This is a simplified implementation - in practice you might want to store
        // commitment indices separately for efficient iteration
        for i in 0..10000 {
            // Reasonable upper bound for iteration
            if let Some(commitment) = self.get_commitment(i)? {
                commitments.push(commitment);
            } else {
                // If we hit a gap, we might have found all commitments
                // This is a heuristic - in practice you'd track the max index
                break;
            }
        }

        Ok(commitments)
    }

    /// Get the root node as a NodeWrapper for operations
    fn get_root_node(&self) -> NodeWrapper {
        NodeWrapper::new(self.serializable.root.to_node())
    }

    /// Update the serializable tree from a NodeWrapper
    fn update_serializable(&mut self, root_node: NodeWrapper) {
        self.serializable.root = SerializableNode::from_node(&root_node.borrow());
        self.root_digest = self.serializable.root.get_hash();
    }
}

#[derive(Debug, Clone)]
pub struct Leaf {
    pub key: String,
    pub value: String,
}

impl Leaf {
    pub fn get_key_digest(&self) -> Digest {
        smt_utils::get_digest(self.key.as_bytes())
    }

    pub fn get_key_bits(&self) -> BitVec<u8, Lsb0> {
        BitVec::from_slice(self.get_key_digest().as_ref())
    }
}

#[derive(Debug, Clone)]
pub struct Branch {
    pub left: NodeWrapper,
    pub right: NodeWrapper,
    pub hash: [u8; 32], // Use concrete type instead of Digest
}

impl Branch {
    pub fn new_branch(left: NodeWrapper, right: NodeWrapper) -> Branch {
        let left_value_digest = left.borrow().get_hash();
        let right_value_digest = right.borrow().get_hash();
        let hash = smt_utils::hash_branch(left_value_digest, right_value_digest);
        let hash_bytes: [u8; 32] = hash.as_ref().try_into().unwrap();
        Branch {
            left,
            right,
            hash: hash_bytes,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub enum Node {
    #[default]
    Empty,
    Leaf(Leaf),
    Branch(Branch),
}

impl Node {
    pub fn get_as_leaf_node(&self) -> Option<Leaf> {
        match self {
            Node::Leaf(leaf) => Some(leaf.clone()),
            _ => None,
        }
    }

    pub fn new_empty() -> Node {
        Node::Empty
    }

    pub fn new_leaf(key: String, value: String) -> Node {
        Node::Leaf(Leaf { key, value })
    }

    pub fn new_branch(left: NodeWrapper, right: NodeWrapper) -> Node {
        Node::Branch(Branch::new_branch(left, right))
    }

    pub fn new_leaf_rc(key: String, value: String) -> NodeWrapper {
        NodeWrapper::new(Node::new_leaf(key, value))
    }

    pub fn new_branch_rc(left: NodeWrapper, right: NodeWrapper) -> NodeWrapper {
        NodeWrapper::new(Node::new_branch(left, right))
    }

    pub fn new_empty_rc() -> NodeWrapper {
        NodeWrapper::new(Node::new_empty())
    }

    pub fn is_empty(&self) -> bool {
        matches!(self, Node::Empty)
    }

    pub fn is_leaf(&self) -> bool {
        matches!(self, Node::Leaf(_))
    }

    pub fn is_branch(&self) -> bool {
        matches!(self, Node::Branch(_))
    }

    pub fn has_non_empty_children(&self) -> bool {
        match self {
            Node::Branch(Branch { left, right, .. }) => {
                !left.borrow().is_empty() && !right.borrow().is_empty()
            }
            _ => false,
        }
    }

    pub fn get_hash(&self) -> Digest {
        match self {
            Node::Leaf(Leaf { key, value }) => smt_utils::hash_kv(key, value),
            Node::Branch(Branch { hash, .. }) => {
                let mut digest = zero_digest();
                digest.as_mut().copy_from_slice(hash);
                digest
            }
            Node::Empty => zero_digest(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SparseMerkleTreeProof {
    pub sibling_hashes: Vec<Digest>,
}

impl AuthenticatedKV for SparseMerkleTree {
    type K = String;
    type V = String;
    type LookupProof = SparseMerkleTreeProof;
    type Commitment = Digest;

    fn new() -> Self {
        Self::new()
    }

    fn commit(&self) -> Self::Commitment {
        self.root_digest
    }

    fn check_proof(
        key: Self::K,
        res: Option<Self::V>,
        pf: &Self::LookupProof,
        comm: &Self::Commitment,
    ) -> Option<()> {
        let mut root_hash = smt_utils::hash_kv(
            &key,
            &res.unwrap_or_else(|| DEFAULT_VALUE_FOR_MISSING.to_string()),
        );

        let binary_key: BitVec<u8, Lsb0> = BitVec::from_slice(smt_utils::get_digest(&key).as_ref());

        let sibling_hashes_len = pf.sibling_hashes.len();

        pf.sibling_hashes
            .iter()
            .enumerate()
            .for_each(|(idx, sibling_hash)| {
                root_hash = if binary_key[sibling_hashes_len - idx - 1] {
                    smt_utils::hash_branch(*sibling_hash, root_hash)
                } else {
                    smt_utils::hash_branch(root_hash, *sibling_hash)
                };
            });

        match &root_hash == comm {
            true => Some(()),
            false => None,
        }
    }

    fn get(&self, key: Self::K) -> (Option<Self::V>, Self::LookupProof) {
        let binary_key: BitVec<u8, Lsb0> = BitVec::from_slice(smt_utils::get_digest(&key).as_ref());

        let mut current_node = self.get_root_node();
        let mut current_node_is_branch = current_node.borrow().is_branch();

        let mut sibling_hashes: Vec<Digest> = vec![];

        let mut height = 0;

        while current_node_is_branch {
            let (left_child, right_child) = match current_node.borrow().clone() {
                Node::Branch(Branch { left, right, .. }) => (left, right),
                _ => panic!("current node is not a branch"),
            };

            let current_node_sibling = if !binary_key[height] {
                current_node = left_child;
                right_child
            } else {
                current_node = right_child;
                left_child
            };

            sibling_hashes.push(current_node_sibling.borrow().get_hash());
            current_node_is_branch = current_node.borrow().is_branch();
            height += 1;
        }

        sibling_hashes.reverse();

        let current_node_cloned = current_node.borrow().clone();
        match current_node_cloned {
            Node::Empty => (None, SparseMerkleTreeProof { sibling_hashes }),
            Node::Leaf(current_node_leaf) => {
                if current_node_leaf.key != key {
                    (None, SparseMerkleTreeProof { sibling_hashes })
                } else {
                    (
                        Some(current_node_leaf.value.clone()),
                        SparseMerkleTreeProof { sibling_hashes },
                    )
                }
            }
            Node::Branch(_) => panic!("current node is branch"),
        }
    }

    fn insert(self, key: Self::K, value: Self::V) -> Self {
        let binary_key: BitVec<u8, Lsb0> = BitVec::from_slice(smt_utils::get_digest(&key).as_ref());

        let mut new_leaf = Node::new_leaf_rc(key.clone(), value);

        let mut ancestor_nodes = Vec::new();

        let mut current_node = self.get_root_node();
        let mut current_node_is_branch = current_node.borrow().is_branch();

        let mut height = 0;

        while current_node_is_branch {
            ancestor_nodes.push(current_node.clone());

            let (left_child, right_child) = match current_node.borrow().clone() {
                Node::Branch(Branch { left, right, .. }) => (left, right),
                _ => panic!("current node is not a branch"),
            };

            current_node = if !binary_key[height] {
                left_child
            } else {
                right_child
            };

            current_node_is_branch = current_node.borrow().is_branch();
            height += 1;
        }

        if let Some(current_node_leaf) = current_node.borrow().get_as_leaf_node() {
            if current_node_leaf.key != key {
                let mut d = binary_key[height];
                let mut t = current_node_leaf.get_key_bits()[height];
                while d == t {
                    if height + 1 >= self.depth {
                        panic!("keys are equal up to max key length: cannot distinguish");
                    }
                    let default_branch =
                        Node::new_branch_rc(Node::new_empty_rc(), Node::new_empty_rc());
                    ancestor_nodes.push(default_branch);
                    height += 1;
                    d = binary_key[height];
                    t = current_node_leaf.get_key_bits()[height];
                }
                if !d {
                    new_leaf = Node::new_branch_rc(
                        new_leaf,
                        NodeWrapper::new(Node::Leaf(current_node_leaf)),
                    );
                } else {
                    new_leaf = Node::new_branch_rc(
                        NodeWrapper::new(Node::Leaf(current_node_leaf)),
                        new_leaf,
                    );
                }
            }
        }

        let mut new_root = new_leaf.clone();
        while height > 0 {
            let d = binary_key[height - 1];
            let p = ancestor_nodes
                .get_mut(height - 1)
                .expect("cannot find node");

            let (left_sibling_node, right_sibling_node) = match p.borrow().clone() {
                Node::Branch(Branch { left, right, .. }) => (left, right),
                _ => panic!("current node is not a branch"),
            };

            if !d {
                *p.borrow_mut() =
                    Node::Branch(Branch::new_branch(new_root.clone(), right_sibling_node));
            } else {
                *p.borrow_mut() =
                    Node::Branch(Branch::new_branch(left_sibling_node, new_root.clone()));
            }

            new_root = p.clone();
            height -= 1;
        }

        let mut result = self;
        result.update_serializable(new_root);
        result
    }
}

pub mod smt_utils {
    use crate::utils::poseidon_hash::internal;

    pub fn hash_kv(k: &str, v: &str) -> crate::tree::common::Digest {
        crate::tree::common::hash_two_things("hash_kv_K", "hash_kv_V", k, v)
    }

    pub fn hash_branch(
        l: crate::tree::common::Digest,
        r: crate::tree::common::Digest,
    ) -> crate::tree::common::Digest {
        crate::tree::common::hash_two_things("hash_branch_L", "hash_branch_R", l, r)
    }

    pub fn get_digest<T: AsRef<[u8]>>(value: T) -> crate::tree::common::Digest {
        // Use the consolidated Poseidon hashing
        let hash = internal::hash_slice(value.as_ref());
        crate::tree::common::Digest(hash)
    }
}

#[cfg(test)]
mod tests {

    use crate::tree::{
        kv_trait::AuthenticatedKV,
        sparse_merkle_tree::{smt_utils::hash_kv, SparseMerkleTree},
    };

    #[test]
    fn insert_root_value() {
        let new_smt = SparseMerkleTree::new();
        let smt = new_smt.insert("key".to_string(), "value".to_string());
        assert_eq!(smt.root_digest, hash_kv("key", "value"));
    }

    #[test]
    fn test_key_replacement() {
        let mut smt = SparseMerkleTree::new();

        // Insert a key
        smt = smt.insert("key1".to_string(), "value1".to_string());
        let (value, _) = smt.get("key1".to_string());
        assert_eq!(value, Some("value1".to_string()));

        // Replace the same key with a new value
        smt = smt.insert("key1".to_string(), "value2".to_string());
        let (value, _) = smt.get("key1".to_string());
        assert_eq!(value, Some("value2".to_string()));

        // Verify proof is still valid
        let (value, proof) = smt.get("key1".to_string());
        assert!(SparseMerkleTree::check_proof(
            "key1".to_string(),
            value.clone(),
            &proof,
            &smt.commit(),
        )
        .is_some());
    }

    #[test]
    fn test_edge_case_similar_keys() {
        let mut smt = SparseMerkleTree::new();

        // Insert keys that differ by only one bit at different positions
        smt = smt.insert("a".to_string(), "value_a".to_string());
        smt = smt.insert("b".to_string(), "value_b".to_string());

        // Verify both keys are retrievable
        let (value_a, _) = smt.get("a".to_string());
        let (value_b, _) = smt.get("b".to_string());
        assert_eq!(value_a, Some("value_a".to_string()));
        assert_eq!(value_b, Some("value_b".to_string()));

        // Verify proofs are valid
        let (value_a, proof_a) = smt.get("a".to_string());
        let (value_b, proof_b) = smt.get("b".to_string());
        assert!(SparseMerkleTree::check_proof(
            "a".to_string(),
            value_a.clone(),
            &proof_a,
            &smt.commit(),
        )
        .is_some());
        assert!(SparseMerkleTree::check_proof(
            "b".to_string(),
            value_b.clone(),
            &proof_b,
            &smt.commit(),
        )
        .is_some());
    }

    #[test]
    fn test_insertion_get_and_proof_verification() {
        let existing_elements = vec![
            ("0", "a"),
            ("1", "b"),
            ("2", "c"),
            ("3", "d"),
            ("4", "e"),
            ("5", "f"),
            ("6", "g"),
            ("7", "h"),
            ("8", "i"),
            ("9", "j"),
            ("10", "k"),
            ("12", "l"),
            ("13", "m"),
        ];

        let non_existing_elements = vec![
            ("14", "n"),
            ("15", "o"),
            ("16", "p"),
            ("17", "q"),
            ("18", "r"),
            ("19", "s"),
            ("20", "t"),
            ("21", "u"),
            ("22", "v"),
            ("23", "w"),
            ("24", "x"),
            ("25", "y"),
            ("26", "z"),
        ];

        // Create sparse merkle tree
        let mut smt = SparseMerkleTree::new();

        // Insert elements
        for (k, v) in existing_elements.iter() {
            smt = smt.insert(k.to_string(), v.to_string());
        }

        // Get existing elements and check inclusive-proof (success)
        for (k, v) in existing_elements.iter() {
            let (value, proof) = smt.get(k.to_string());
            assert_eq!(value, Some(v.to_string()));
            assert!(SparseMerkleTree::check_proof(
                k.to_string(),
                value.clone(),
                &proof,
                &smt.commit(),
            )
            .is_some());
        }

        // Get non-existing elements and check inclusive-proof (failure)
        for (k, _) in non_existing_elements.iter() {
            let (value, proof) = smt.get(k.to_string());
            assert_eq!(value, None);
            assert!(SparseMerkleTree::check_proof(
                k.to_string(),
                value.clone(),
                &proof,
                &smt.commit()
            )
            .is_none());
        }
    }
}
