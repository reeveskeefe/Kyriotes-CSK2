use sha2::{Digest, Sha256};

use crate::core::error::ArcError;

use super::model::{AuthorityState, TransparencyProof, transparency_leaf_hash};

pub trait TransparencyLog {
    fn commit_state(&mut self, state: &AuthorityState) -> Result<TransparencyStateCommit, ArcError>;
    fn proof_for_state(&self, state: &AuthorityState) -> Result<TransparencyProof, ArcError>;
    fn current_root(&self) -> [u8; 32];
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransparencyStateCommit {
    pub state: AuthorityState,
    pub proof: TransparencyProof,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TransparencyEntry {
    authority_id: String,
    epoch: u64,
    leaf_hash: [u8; 32],
}

#[derive(Clone, Debug, Default)]
pub struct InMemoryTransparencyLog {
    entries: Vec<TransparencyEntry>,
}

impl InMemoryTransparencyLog {
    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }

    fn find_index(&self, authority_id: &str, epoch: u64) -> Option<usize> {
        self.entries
            .iter()
            .position(|e| e.authority_id == authority_id && e.epoch == epoch)
    }

    fn leaf_hashes(&self) -> Vec<[u8; 32]> {
        self.entries.iter().map(|e| e.leaf_hash).collect()
    }

    fn proof_for_index(&self, index: usize) -> Result<TransparencyProof, ArcError> {
        if self.entries.is_empty() {
            return Err(ArcError::AuthorityState("transparency log is empty"));
        }
        if index >= self.entries.len() {
            return Err(ArcError::AuthorityState("transparency log index out of bounds"));
        }

        let leaves = self.leaf_hashes();
        let sibling_hashes = merkle_proof_for_index(&leaves, index);

        Ok(TransparencyProof {
            leaf_hash: leaves[index],
            sibling_hashes,
            leaf_index: index as u64,
        })
    }
}

impl TransparencyLog for InMemoryTransparencyLog {
    fn commit_state(&mut self, state: &AuthorityState) -> Result<TransparencyStateCommit, ArcError> {
        let leaf_hash = transparency_leaf_hash(state);

        let index = if let Some(existing_index) = self.find_index(&state.authority_id, state.epoch) {
            if self.entries[existing_index].leaf_hash != leaf_hash {
                return Err(ArcError::AuthorityState(
                    "transparency log already contains different state for authority/epoch",
                ));
            }
            existing_index
        } else {
            self.entries.push(TransparencyEntry {
                authority_id: state.authority_id.clone(),
                epoch: state.epoch,
                leaf_hash,
            });
            self.entries.len() - 1
        };

        let root = self.current_root();
        let proof = self.proof_for_index(index)?;

        let mut committed_state = state.clone();
        committed_state.transparency_root = root;

        Ok(TransparencyStateCommit {
            state: committed_state,
            proof,
        })
    }

    fn proof_for_state(&self, state: &AuthorityState) -> Result<TransparencyProof, ArcError> {
        let idx = self
            .find_index(&state.authority_id, state.epoch)
            .ok_or(ArcError::AuthorityState(
                "state not found in transparency log",
            ))?;

        let expected_leaf = transparency_leaf_hash(state);
        if self.entries[idx].leaf_hash != expected_leaf {
            return Err(ArcError::AuthorityState(
                "transparency log leaf does not match authority state",
            ));
        }

        self.proof_for_index(idx)
    }

    fn current_root(&self) -> [u8; 32] {
        let leaves = self.leaf_hashes();
        merkle_root(&leaves)
    }
}

pub fn hash_transparency_node(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ARC-TRANSPARENCY-NODE-v1");
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }

    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0usize;
        while i < level.len() {
            let left = level[i];
            let right = if i + 1 < level.len() { level[i + 1] } else { level[i] };
            next.push(hash_transparency_node(left, right));
            i += 2;
        }
        level = next;
    }

    level[0]
}

fn merkle_proof_for_index(leaves: &[[u8; 32]], index: usize) -> Vec<[u8; 32]> {
    if leaves.is_empty() {
        return Vec::new();
    }

    let mut siblings = Vec::new();
    let mut idx = index;
    let mut level: Vec<[u8; 32]> = leaves.to_vec();

    while level.len() > 1 {
        let sibling_idx = if idx % 2 == 0 {
            if idx + 1 < level.len() {
                idx + 1
            } else {
                idx
            }
        } else {
            idx - 1
        };

        siblings.push(level[sibling_idx]);

        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0usize;
        while i < level.len() {
            let left = level[i];
            let right = if i + 1 < level.len() { level[i + 1] } else { level[i] };
            next.push(hash_transparency_node(left, right));
            i += 2;
        }

        idx /= 2;
        level = next;
    }

    siblings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_state(epoch: u64) -> AuthorityState {
        AuthorityState {
            authority_root: [epoch as u8; 32],
            revocation_root: [(epoch as u8).wrapping_add(1); 32],
            transparency_root: [0u8; 32],
            epoch,
            authority_id: "auth-main".to_string(),
            epoch_signature_valid: true,
            epoch_key_cert_valid: true,
            transparency_inclusion_valid: true,
        }
    }

    #[test]
    fn commit_produces_state_root_and_proof() {
        let mut log = InMemoryTransparencyLog::new();
        let commit = log
            .commit_state(&sample_state(42))
            .expect("commit should succeed");

        assert_ne!(commit.state.transparency_root, [0u8; 32]);
        assert_eq!(commit.proof.leaf_index, 0);
        assert_eq!(commit.proof.leaf_hash, transparency_leaf_hash(&sample_state(42)));
    }

    #[test]
    fn proof_for_state_rejects_missing_state() {
        let log = InMemoryTransparencyLog::new();
        let err = log
            .proof_for_state(&sample_state(42))
            .expect_err("missing state should fail");
        assert!(matches!(err, ArcError::AuthorityState("state not found in transparency log")));
    }
}
