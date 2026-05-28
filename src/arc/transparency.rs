use sha2::{Digest, Sha256};

use crate::core::error::ArcError;

use super::model::{AuthorityState, TransparencyProof, transparency_leaf_hash};

pub trait TransparencyLog {
    fn commit_state(&mut self, state: &AuthorityState)
    -> Result<TransparencyStateCommit, ArcError>;
    fn proof_for_state(&self, state: &AuthorityState) -> Result<TransparencyProof, ArcError>;
    fn current_root(&self) -> [u8; 32];

    /// Store the transparency chain hash `Log_e` computed by
    /// [`transparency_log_entry_hash`] for the given `(authority_id, epoch)`.
    ///
    /// Called after [`commit_state`] by [`rotate_epoch_and_commit`] once
    /// `sigma_e` is available.  Default implementation is a no-op; log
    /// implementations that want chain-hash auditing should override this.
    fn store_chain_hash(&mut self, _authority_id: &str, _epoch: u64, _chain_hash: [u8; 32]) {}

    /// Look up the stored chain hash `Log_e` for `(authority_id, epoch)`, if any.
    fn chain_hash_for(&self, _authority_id: &str, _epoch: u64) -> Option<[u8; 32]> {
        None
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransparencyStateCommit {
    pub state: AuthorityState,
    pub proof: TransparencyProof,
    /// The transparency log chain hash `Log_e` computed from this epoch's
    /// epoch key and root signature (spec §8 / §25i).  `[0u8; 32]` when the
    /// commit was created via a bare [`TransparencyLog::commit_state`] call
    /// that did not have access to `sigma_e`; populated by
    /// [`rotate_epoch_and_commit`].
    pub chain_hash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TransparencyEntry {
    authority_id: String,
    epoch: u64,
    leaf_hash: [u8; 32],
    /// The `Log_e` chain hash registered via [`TransparencyLog::store_chain_hash`].
    /// `[0u8; 32]` until explicitly set.
    chain_hash: [u8; 32],
}

#[derive(Clone, Debug, Default)]
pub struct InMemoryTransparencyLog {
    entries: Vec<TransparencyEntry>,
}

impl InMemoryTransparencyLog {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
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
            return Err(ArcError::AuthorityState(
                "transparency log index out of bounds",
            ));
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
    fn commit_state(
        &mut self,
        state: &AuthorityState,
    ) -> Result<TransparencyStateCommit, ArcError> {
        let leaf_hash = transparency_leaf_hash(state);

        let index = if let Some(existing_index) = self.find_index(&state.authority_id, state.epoch)
        {
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
                chain_hash: [0u8; 32],
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
            chain_hash: [0u8; 32],
        })
    }

    fn proof_for_state(&self, state: &AuthorityState) -> Result<TransparencyProof, ArcError> {
        let idx =
            self.find_index(&state.authority_id, state.epoch)
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

    fn store_chain_hash(&mut self, authority_id: &str, epoch: u64, chain_hash: [u8; 32]) {
        if let Some(idx) = self.find_index(authority_id, epoch) {
            self.entries[idx].chain_hash = chain_hash;
        }
    }

    fn chain_hash_for(&self, authority_id: &str, epoch: u64) -> Option<[u8; 32]> {
        self.find_index(authority_id, epoch)
            .map(|idx| self.entries[idx].chain_hash)
    }
}

/// Padding applied to a lone node (odd-sized level) when it has no pair.
/// Using a fixed all-`0xFF` pattern that is distinct from `[0u8; 32]` (the
/// empty-tree root) and from any realistic SHA-256 output, preventing the
/// duplicate-last-leaf second-preimage attack (CVE-2012-2459 class):
///
/// Without this fix a 3-leaf tree and a 4-leaf tree whose 4th leaf equals
/// its 3rd share the same root because the builder used `H(L, L)` for the
/// lone node.  With the sentinel the lone-node parent is `H(L, 0xFF…FF)`,
/// which is distinct from any pair result `H(L, L')` for a real L'.
pub const LONE_NODE_SENTINEL: [u8; 32] = [0xff; 32];

pub fn hash_transparency_node(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ARC-TRANSPARENCY-NODE-v1");
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Compute the transparency log chain hash `Log_e` per spec §8 / §25i.
///
/// For the genesis epoch (`epoch == 0`) the domain separator
/// `"ARC-LOG-GENESIS-v1"` replaces `prev_hash` in the input; for all
/// subsequent epochs the raw `prev_hash` bytes (`Log_{e-1}`) are used.
///
/// The returned value should be stored as `prev_epoch_hash` in the *next*
/// epoch's [`AuthorityState`] and passed as `prev_epoch_hash` when signing
/// that epoch's root signature.
pub fn transparency_log_entry_hash(
    prev_hash: &[u8; 32],
    authority_root: &[u8; 32],
    revocation_root: &[u8; 32],
    epoch: u64,
    epoch_pk: &[u8; 32],
    epoch_root_sig: &[u8; 64],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    if epoch == 0 {
        hasher.update(b"ARC-LOG-GENESIS-v1");
    } else {
        hasher.update(prev_hash);
    }
    hasher.update(authority_root);
    hasher.update(revocation_root);
    hasher.update(epoch.to_le_bytes());
    hasher.update(epoch_pk);
    hasher.update(epoch_root_sig);
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
            // Use LONE_NODE_SENTINEL for unpaired nodes instead of
            // self-duplication, preventing the duplicate-leaf second-preimage.
            let right = if i + 1 < level.len() {
                level[i + 1]
            } else {
                LONE_NODE_SENTINEL
            };
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
        // Record the sibling used at this level.  For a lone (unpaired) node
        // the sibling is LONE_NODE_SENTINEL, matching what merkle_root builds.
        if idx.is_multiple_of(2) {
            if idx + 1 < level.len() {
                siblings.push(level[idx + 1]);
            } else {
                siblings.push(LONE_NODE_SENTINEL);
            }
        } else {
            siblings.push(level[idx - 1]);
        }

        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0usize;
        while i < level.len() {
            let left = level[i];
            let right = if i + 1 < level.len() {
                level[i + 1]
            } else {
                LONE_NODE_SENTINEL
            };
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
            root_pk: [0u8; 32],
            revocation_count: 0,
            prev_epoch_hash: [0u8; 32],
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
        assert_eq!(
            commit.proof.leaf_hash,
            transparency_leaf_hash(&sample_state(42))
        );
    }

    #[test]
    fn proof_for_state_rejects_missing_state() {
        let log = InMemoryTransparencyLog::new();
        let err = log
            .proof_for_state(&sample_state(42))
            .expect_err("missing state should fail");
        assert!(matches!(
            err,
            ArcError::AuthorityState("state not found in transparency log")
        ));
    }
}
