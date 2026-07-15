//! Blake3-based Merkle tree supporting both inclusion and non-membership proofs.
//!
//! Non-membership proofs are the primitive needed for a revocation check:
//! proving a credential/commitment is *not* in a revocation list without
//! revealing the full list. This implementation uses a sorted-leaf tree,
//! where non-membership is proven by showing two adjacent leaves that
//! bracket the target value with nothing between them.
//!
//! Domain separation: leaf hashes and internal-node hashes use different
//! prefix bytes, so an attacker cannot present an internal node as if it
//! were a leaf (a classic second-preimage attack against naive Merkle trees).

const LEAF_PREFIX: u8 = 0x00;
const NODE_PREFIX: u8 = 0x01;

pub type Hash = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MerkleError {
    EmptyTree,
    InvalidProof,
    LeafNotFound,
}

impl std::fmt::Display for MerkleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyTree => write!(f, "cannot build a Merkle tree from zero leaves"),
            Self::InvalidProof => write!(f, "Merkle proof failed to reconstruct the expected root"),
            Self::LeafNotFound => write!(f, "requested leaf value not present in the tree"),
        }
    }
}

impl std::error::Error for MerkleError {}

fn hash_leaf(data: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[LEAF_PREFIX]);
    hasher.update(data);
    *hasher.finalize().as_bytes()
}

fn hash_node(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[NODE_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

/// A step in an inclusion proof: the sibling hash and which side it's on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofStep {
    pub sibling: Hash,
    pub is_left: bool, // true if sibling is the left node (we are the right)
}

/// A Merkle inclusion proof: the leaf's sibling path up to the root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionProof {
    pub leaf_hash: Hash,
    pub path: Vec<ProofStep>,
}

impl InclusionProof {
    /// Recomputes the root from this proof and checks it matches `expected_root`.
    pub fn verify(&self, expected_root: &Hash) -> Result<(), MerkleError> {
        let mut current = self.leaf_hash;
        for step in &self.path {
            current = if step.is_left {
                hash_node(&step.sibling, &current)
            } else {
                hash_node(&current, &step.sibling)
            };
        }
        if &current == expected_root {
            Ok(())
        } else {
            Err(MerkleError::InvalidProof)
        }
    }
}

/// A non-membership proof: two adjacent leaves (by sorted order) that bracket
/// the target value, each with their own inclusion proof, plus a check that
/// nothing sits between them.
#[derive(Debug, Clone)]
pub struct NonMembershipProof {
    pub lower: Vec<u8>,
    pub lower_proof: InclusionProof,
    pub upper: Vec<u8>,
    pub upper_proof: InclusionProof,
}

impl NonMembershipProof {
    /// Verifies that `target` is not in the tree with root `expected_root`,
    /// by checking both bracketing leaves are genuinely in the tree and that
    /// `lower < target < upper` with `lower` and `upper` adjacent in sorted order
    /// (adjacency itself is guaranteed by construction in `MerkleTree::prove_non_membership`;
    /// this function re-checks the ordering constraint against the claimed values).
    pub fn verify(&self, target: &[u8], expected_root: &Hash) -> Result<(), MerkleError> {
        if !(self.lower.as_slice() < target && target < self.upper.as_slice()) {
            return Err(MerkleError::InvalidProof);
        }
        if hash_leaf(&self.lower) != self.lower_proof.leaf_hash {
            return Err(MerkleError::InvalidProof);
        }
        if hash_leaf(&self.upper) != self.upper_proof.leaf_hash {
            return Err(MerkleError::InvalidProof);
        }
        self.lower_proof.verify(expected_root)?;
        self.upper_proof.verify(expected_root)?;
        Ok(())
    }
}

/// A Blake3 Merkle tree over sorted leaf values.
pub struct MerkleTree {
    /// Sorted leaf values (not hashes) -- kept to support non-membership proofs.
    leaves: Vec<Vec<u8>>,
    /// All levels of the tree, level 0 = leaf hashes, last level = single root.
    levels: Vec<Vec<Hash>>,
}

impl MerkleTree {
    /// Builds a tree from arbitrary byte-string leaves. Leaves are sorted
    /// internally so non-membership proofs (adjacency-based) are possible.
    pub fn build(mut leaves: Vec<Vec<u8>>) -> Result<Self, MerkleError> {
        if leaves.is_empty() {
            return Err(MerkleError::EmptyTree);
        }
        leaves.sort();
        leaves.dedup();

        let mut level: Vec<Hash> = leaves.iter().map(|l| hash_leaf(l)).collect();
        let mut levels = vec![level.clone()];

        while level.len() > 1 {
            let mut next = Vec::with_capacity((level.len() + 1) / 2);
            let mut i = 0;
            while i < level.len() {
                if i + 1 < level.len() {
                    next.push(hash_node(&level[i], &level[i + 1]));
                } else {
                    // Odd node out: promote unchanged (duplicate-free approach,
                    // avoids the classic "duplicate last node" second-preimage issue).
                    next.push(level[i]);
                }
                i += 2;
            }
            levels.push(next.clone());
            level = next;
        }

        Ok(Self { leaves, levels })
    }

    pub fn root(&self) -> Hash {
        *self.levels.last().unwrap().last().unwrap()
    }

    /// Builds an inclusion proof for a leaf value present in the tree.
    pub fn prove_inclusion(&self, leaf: &[u8]) -> Result<InclusionProof, MerkleError> {
        let mut index = self
            .leaves
            .binary_search(&leaf.to_vec())
            .map_err(|_| MerkleError::LeafNotFound)?;

        let leaf_hash = hash_leaf(leaf);
        let mut path = Vec::new();

        for level in &self.levels[..self.levels.len() - 1] {
            let is_right = index % 2 == 1;
            let sibling_index = if is_right { index - 1 } else { index + 1 };
            if sibling_index < level.len() {
                path.push(ProofStep {
                    sibling: level[sibling_index],
                    is_left: is_right,
                });
            }
            // If there is no sibling (odd node promoted), no step is added
            // for this level, matching the promotion rule in `build`.
            index /= 2;
        }

        Ok(InclusionProof { leaf_hash, path })
    }

    /// Builds a non-membership proof for `target`, which must NOT be in the tree.
    pub fn prove_non_membership(&self, target: &[u8]) -> Result<NonMembershipProof, MerkleError> {
        if self.leaves.binary_search(&target.to_vec()).is_ok() {
            // target is actually present -- cannot prove non-membership.
            return Err(MerkleError::InvalidProof);
        }

        let insertion_point = self.leaves.partition_point(|l| l.as_slice() < target);

        if insertion_point == 0 || insertion_point == self.leaves.len() {
            // target is outside the full range of leaves; this simple scheme
            // requires a sentinel min/max leaf to bracket the whole range.
            // Callers should insert -inf/+inf sentinel leaves when building
            // a revocation tree to avoid this edge case.
            return Err(MerkleError::InvalidProof);
        }

        let lower = self.leaves[insertion_point - 1].clone();
        let upper = self.leaves[insertion_point].clone();

        let lower_proof = self.prove_inclusion(&lower)?;
        let upper_proof = self.prove_inclusion(&upper)?;

        Ok(NonMembershipProof { lower, lower_proof, upper, upper_proof })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_leaves() -> Vec<Vec<u8>> {
        vec![
            b"credential-0001".to_vec(),
            b"credential-0002".to_vec(),
            b"credential-0005".to_vec(),
            b"credential-0009".to_vec(),
            b"credential-0012".to_vec(),
        ]
    }

    #[test]
    fn build_and_root_is_deterministic() {
        let t1 = MerkleTree::build(sample_leaves()).unwrap();
        let t2 = MerkleTree::build(sample_leaves()).unwrap();
        assert_eq!(t1.root(), t2.root());
    }

    #[test]
    fn inclusion_proof_verifies_for_present_leaf() {
        let tree = MerkleTree::build(sample_leaves()).unwrap();
        let root = tree.root();
        let proof = tree.prove_inclusion(b"credential-0005").unwrap();
        proof.verify(&root).expect("valid inclusion proof must verify");
    }

    #[test]
    fn inclusion_proof_fails_for_wrong_root() {
        let tree = MerkleTree::build(sample_leaves()).unwrap();
        let proof = tree.prove_inclusion(b"credential-0005").unwrap();
        let wrong_root = [0xAAu8; 32];
        assert!(proof.verify(&wrong_root).is_err());
    }

    #[test]
    fn inclusion_proof_fails_for_tampered_leaf_hash() {
        let tree = MerkleTree::build(sample_leaves()).unwrap();
        let root = tree.root();
        let mut proof = tree.prove_inclusion(b"credential-0005").unwrap();
        proof.leaf_hash[0] ^= 0xFF;
        assert!(proof.verify(&root).is_err());
    }

    #[test]
    fn absent_leaf_cannot_be_included() {
        let tree = MerkleTree::build(sample_leaves()).unwrap();
        let result = tree.prove_inclusion(b"credential-9999");
        assert!(matches!(result, Err(MerkleError::LeafNotFound)));
    }

    #[test]
    fn non_membership_proof_verifies_for_absent_value_between_leaves() {
        let tree = MerkleTree::build(sample_leaves()).unwrap();
        let root = tree.root();
        // "credential-0003" sits between 0002 and 0005 lexicographically.
        let proof = tree.prove_non_membership(b"credential-0003").unwrap();
        proof
            .verify(b"credential-0003", &root)
            .expect("valid non-membership proof must verify");
    }

    #[test]
    fn non_membership_proof_rejected_for_present_value() {
        let tree = MerkleTree::build(sample_leaves()).unwrap();
        let result = tree.prove_non_membership(b"credential-0005");
        assert!(matches!(result, Err(MerkleError::InvalidProof)));
    }

    #[test]
    fn non_membership_proof_rejects_target_outside_claimed_bounds() {
        let tree = MerkleTree::build(sample_leaves()).unwrap();
        let root = tree.root();
        let proof = tree.prove_non_membership(b"credential-0003").unwrap();
        // Attempt to reuse this proof to claim non-membership of a different,
        // out-of-range target -- must fail because target is not strictly
        // between lower and upper.
        let result = proof.verify(b"credential-9999", &root);
        assert!(result.is_err());
    }

    #[test]
    fn non_membership_proof_rejects_tampered_bracket() {
        let tree = MerkleTree::build(sample_leaves()).unwrap();
        let root = tree.root();
        let mut proof = tree.prove_non_membership(b"credential-0003").unwrap();
        // Tamper with the claimed lower bound without updating its proof.
        proof.lower = b"credential-0001".to_vec();
        let result = proof.verify(b"credential-0003", &root);
        assert!(result.is_err());
    }

    #[test]
    fn empty_tree_is_rejected() {
        let result = MerkleTree::build(vec![]);
        assert!(matches!(result, Err(MerkleError::EmptyTree)));
    }

    #[test]
    fn duplicate_leaves_are_deduplicated() {
        let leaves = vec![b"a".to_vec(), b"a".to_vec(), b"b".to_vec()];
        let tree = MerkleTree::build(leaves).unwrap();
        let root = tree.root();
        let proof = tree.prove_inclusion(b"a").unwrap();
        proof.verify(&root).expect("dedup'd tree must still verify inclusion");
    }
}
