//! Authority capability tree — spec §6 (Authority State and Roots).
//!
//! ARC authorities maintain two sets per epoch:
//!
//! - **L_e** — the active capability set; `R_e = MerkleRoot(L_e)` is the
//!   `authority_root` stored in `AuthorityState` and sealed into every wrapper.
//! - **V_e** — the revoked stamp set; `Rev_e = MerkleRoot(V_e)` is the
//!   `revocation_root`.
//!
//! `AuthorityCapabilityTree` is the in-process authority-side implementation
//! of these two trees, analogous to `InMemoryTransparencyLog` on the verifier
//! side.  It also supports generating `CapabilityInclusionProof` values and
//! verifying them (spec §9, predicate point 1).
//!
//! Spec §9 predicate point 7 (issuance signature) is handled by
//! `CapabilityIssuanceProof` + `verify_capability_issuance`.

use ed25519_dalek::{Signature, VerifyingKey};

use crate::core::error::ArcError;

use super::authority::{
    capability_issuance_signing_message, verify_epoch_cert, EpochKeyCert,
};
use super::model::{capability_leaf_hash, capability_stamp, AuthorityState, Capability};
use super::transparency::{hash_transparency_node, merkle_root};

// ---------------------------------------------------------------------------
// Proof types
// ---------------------------------------------------------------------------

/// Merkle inclusion proof showing a capability is in `R_e = MerkleRoot(L_e)`.
///
/// Structurally identical to `TransparencyProof`; kept as a separate type so
/// the domain is clear in function signatures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityInclusionProof {
    /// Expected leaf hash (`capability_leaf_hash(cap)`).
    pub leaf_hash: [u8; 32],
    /// Sibling hashes along the Merkle path from leaf to root.
    pub sibling_hashes: Vec<[u8; 32]>,
    /// 0-based position of this leaf in the tree.
    pub leaf_index: u64,
}

/// Proof that an epoch authority issued a capability (spec §9 point 7).
///
/// Contains the epoch online key's signature over the issuance message and
/// the `EpochKeyCert` that ties the epoch key back to the offline root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityIssuanceProof {
    /// Ed25519 signature by `sk_A_e` over `capability_issuance_signing_message(...)`.
    pub sig: [u8; 64],
    /// Certificate from the offline root binding `sig`'s key to the epoch.
    pub epoch_cert: EpochKeyCert,
}

/// One adjacent boundary element in a sorted-Merkle non-revocation witness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NonRevocationBound {
    /// The boundary stamp value.
    pub stamp: [u8; 32],
    /// Merkle inclusion proof for `stamp` in the revocation tree `Rev_e`.
    pub proof: CapabilityInclusionProof,
}

/// Sorted-Merkle non-revocation witness (spec §9 predicate point 2).
///
/// Proves that `stamp` is absent from `V_e` by showing the two adjacent
/// sorted elements that would bracket it, along with their Merkle inclusion
/// proofs.  Boundary cases (stamp smaller or larger than all revoked stamps,
/// or an empty revocation set) are represented by omitting the missing side.
///
/// Security relies on `V_e` being maintained in sorted order so that
/// `left.leaf_index + 1 == right.leaf_index` (when both are present) proves
/// no element exists between them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NonRevocationWitness {
    /// The stamp whose absence is being proved.
    pub stamp: [u8; 32],
    /// Total number of stamps in `V_e`.
    pub total_revoked: u64,
    /// Largest stamp in `V_e` that is less than `stamp`, with its Merkle proof.
    /// `None` when `stamp` is smaller than every revoked stamp, or `V_e` is empty.
    pub left: Option<NonRevocationBound>,
    /// Smallest stamp in `V_e` that is greater than `stamp`, with its Merkle proof.
    /// `None` when `stamp` is larger than every revoked stamp, or `V_e` is empty.
    pub right: Option<NonRevocationBound>,
}

// ---------------------------------------------------------------------------
// Authority capability tree
// ---------------------------------------------------------------------------

/// In-process authority-side implementation of the capability and revocation
/// Merkle trees (spec §6).
///
/// Intended for use by authority processes that issue and revoke capabilities.
/// Verifier processes receive the resulting roots (`authority_root`,
/// `revocation_root`) through `AuthorityState`.
#[derive(Debug, Default)]
pub struct AuthorityCapabilityTree {
    /// Active capability leaf hashes (`L_e`).
    leaf_hashes: Vec<[u8; 32]>,
    /// Revoked capability stamps (`V_e`).
    revoked_stamps: Vec<[u8; 32]>,
}

impl AuthorityCapabilityTree {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a capability to the active set.
    ///
    /// Idempotent: re-adding the same capability is a no-op.
    /// Returns the capability's leaf hash.
    pub fn add_capability(&mut self, cap: &Capability) -> [u8; 32] {
        let leaf_hash = capability_leaf_hash(cap);
        if !self.leaf_hashes.contains(&leaf_hash) {
            self.leaf_hashes.push(leaf_hash);
        }
        leaf_hash
    }

    /// Add a raw stamp to the revocation set.
    ///
    /// The set is kept in ascending byte-lexicographic order so that sorted
    /// Merkle non-membership proofs can be generated with `non_revocation_witness`.
    /// Idempotent — adding the same stamp twice is a no-op.
    pub fn revoke_stamp(&mut self, stamp: [u8; 32]) {
        let pos = self.revoked_stamps.partition_point(|s| s < &stamp);
        if pos < self.revoked_stamps.len() && self.revoked_stamps[pos] == stamp {
            return; // already present
        }
        self.revoked_stamps.insert(pos, stamp);
    }

    /// Revoke a capability by computing and adding its stamp.
    ///
    /// The stamp depends on the authority state at revocation time; pass the
    /// state that will be published with this revocation.
    pub fn revoke_capability(&mut self, cap: &Capability, state: &AuthorityState) {
        let stamp = capability_stamp(cap, state);
        self.revoke_stamp(stamp);
    }

    /// Generate a sorted-Merkle non-revocation witness for `stamp`.
    ///
    /// Returns `Err` if `stamp` is already in `V_e` (the capability is revoked).
    /// Otherwise returns a witness containing boundary proofs that together
    /// prove `stamp ∉ V_e` under the current `revocation_root()`.
    pub fn non_revocation_witness(
        &self,
        stamp: &[u8; 32],
    ) -> Result<NonRevocationWitness, ArcError> {
        let pos = self.revoked_stamps.partition_point(|s| s < stamp);
        if pos < self.revoked_stamps.len() && &self.revoked_stamps[pos] == stamp {
            return Err(ArcError::InvalidCapability("capability is revoked; no non-revocation witness possible"));
        }

        let total_revoked = self.revoked_stamps.len() as u64;

        let left = if pos > 0 {
            let idx = pos - 1;
            let ls = self.revoked_stamps[idx];
            let proof = self.revocation_proof_for_index(idx);
            Some(NonRevocationBound { stamp: ls, proof })
        } else {
            None
        };

        let right = if pos < self.revoked_stamps.len() {
            let rs = self.revoked_stamps[pos];
            let proof = self.revocation_proof_for_index(pos);
            Some(NonRevocationBound { stamp: rs, proof })
        } else {
            None
        };

        Ok(NonRevocationWitness { stamp: *stamp, total_revoked, left, right })
    }

    fn revocation_proof_for_index(&self, index: usize) -> CapabilityInclusionProof {
        let leaf_hash = self.revoked_stamps[index];
        let sibling_hashes = merkle_proof_for_index(&self.revoked_stamps, index);
        CapabilityInclusionProof { leaf_hash, sibling_hashes, leaf_index: index as u64 }
    }

    /// `R_e = MerkleRoot(L_e)` — authority root over active capabilities.
    pub fn authority_root(&self) -> [u8; 32] {
        merkle_root(&self.leaf_hashes)
    }

    /// `Rev_e = MerkleRoot(V_e)` — revocation root over revoked stamps.
    pub fn revocation_root(&self) -> [u8; 32] {
        merkle_root(&self.revoked_stamps)
    }

    /// Generate a Merkle inclusion proof for `cap` in `L_e`.
    ///
    /// Returns `None` if the capability has not been added to this tree.
    pub fn inclusion_proof(&self, cap: &Capability) -> Option<CapabilityInclusionProof> {
        let leaf_hash = capability_leaf_hash(cap);
        let index = self.leaf_hashes.iter().position(|h| h == &leaf_hash)?;
        let sibling_hashes = merkle_proof_for_index(&self.leaf_hashes, index);
        Some(CapabilityInclusionProof {
            leaf_hash,
            sibling_hashes,
            leaf_index: index as u64,
        })
    }

    /// Check whether `stamp` is in `V_e` (capability is revoked).
    pub fn is_revoked(&self, stamp: &[u8; 32]) -> bool {
        self.revoked_stamps.contains(stamp)
    }

    /// Number of active capabilities in `L_e`.
    pub fn len(&self) -> usize {
        self.leaf_hashes.len()
    }

    /// True if `L_e` is empty.
    pub fn is_empty(&self) -> bool {
        self.leaf_hashes.is_empty()
    }

    /// Number of entries in the revocation set `V_e`.
    ///
    /// Store this in `AuthorityState::revocation_count` so that
    /// `verify_non_revocation` can authenticate the witness's `total_revoked`
    /// claim rather than trusting prover-supplied data.
    pub fn revocation_count(&self) -> u64 {
        self.revoked_stamps.len() as u64
    }
}

// ---------------------------------------------------------------------------
// Merkle proof generation (mirrors InMemoryTransparencyLog::proof_for_index)
// ---------------------------------------------------------------------------

fn merkle_proof_for_index(leaves: &[[u8; 32]], index: usize) -> Vec<[u8; 32]> {
    if leaves.is_empty() || index >= leaves.len() {
        return Vec::new();
    }

    let mut siblings = Vec::new();
    let mut idx = index;
    let mut level: Vec<[u8; 32]> = leaves.to_vec();

    while level.len() > 1 {
        let sibling_idx = if idx % 2 == 0 {
            if idx + 1 < level.len() { idx + 1 } else { idx }
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
        level = next;
        idx /= 2;
    }

    siblings
}

// ---------------------------------------------------------------------------
// Shared Merkle path verification
// ---------------------------------------------------------------------------

/// Walk a Merkle proof path and return true iff the computed root matches.
fn verify_merkle_path(
    leaf: &[u8; 32],
    sibling_hashes: &[[u8; 32]],
    leaf_index: u64,
    root: &[u8; 32],
) -> bool {
    let mut idx = leaf_index;
    let mut acc = *leaf;
    for sibling in sibling_hashes {
        acc = if idx & 1 == 0 {
            hash_transparency_node(acc, *sibling)
        } else {
            hash_transparency_node(*sibling, acc)
        };
        idx >>= 1;
    }
    &acc == root
}

// ---------------------------------------------------------------------------
// Standalone verifiers
// ---------------------------------------------------------------------------

/// Verify that `cap` is included in the Merkle tree whose root is
/// `authority_root` (spec §9 predicate point 1).
pub fn verify_capability_inclusion(
    cap: &Capability,
    proof: &CapabilityInclusionProof,
    authority_root: &[u8; 32],
) -> Result<(), ArcError> {
    let expected_leaf = capability_leaf_hash(cap);
    if proof.leaf_hash != expected_leaf {
        return Err(ArcError::InvalidCapability(
            "inclusion proof leaf hash does not match capability",
        ));
    }
    if !verify_merkle_path(&proof.leaf_hash, &proof.sibling_hashes, proof.leaf_index, authority_root) {
        return Err(ArcError::InvalidCapability(
            "capability Merkle inclusion proof root mismatch",
        ));
    }
    Ok(())
}

/// Verify a sorted-Merkle non-revocation witness (spec §9 predicate point 2).
///
/// The witness proves `stamp ∉ V_e` under the authenticated `revocation_root`.
/// `expected_revocation_count` is the authenticated count of entries in `V_e`,
/// taken from `AuthorityState::revocation_count` (which is committed in the
/// transparency leaf hash and thus cannot be forged by the prover).
///
/// **Security note**: do not pass `witness.total_revoked` as `expected_revocation_count`;
/// the point of this parameter is to provide an independently authenticated value.
///
/// Verification rules:
/// - **Empty set** (`expected_revocation_count == 0`): `revocation_root` must be
///   `[0u8;32]`; both `left` and `right` must be absent.
/// - **Left boundary only**: `left.stamp < stamp` and `left` is the rightmost
///   leaf (`left.proof.leaf_index == expected_revocation_count - 1`).
/// - **Right boundary only**: `right.stamp > stamp` and `right` is the leftmost
///   leaf (`right.proof.leaf_index == 0`).
/// - **Both boundaries**: `left.stamp < stamp < right.stamp` and adjacent
///   (`left.proof.leaf_index + 1 == right.proof.leaf_index`).
pub fn verify_non_revocation(
    witness: &NonRevocationWitness,
    revocation_root: &[u8; 32],
    expected_revocation_count: u64,
) -> Result<(), ArcError> {
    // Verify witness.total_revoked against the authenticated count from state.
    if witness.total_revoked != expected_revocation_count {
        return Err(ArcError::InvalidCapability(
            "non-revocation witness total_revoked does not match authority revocation_count",
        ));
    }

    if witness.total_revoked == 0 {
        if revocation_root != &[0u8; 32] {
            return Err(ArcError::InvalidCapability(
                "non-revocation witness claims empty set but revocation root is non-zero",
            ));
        }
        if witness.left.is_some() || witness.right.is_some() {
            return Err(ArcError::InvalidCapability(
                "non-revocation witness has bounds but claims empty revocation set",
            ));
        }
        return Ok(());
    }

    // Verify each boundary inclusion proof and check ordering.
    if let Some(left) = &witness.left {
        if left.proof.leaf_hash != left.stamp {
            return Err(ArcError::InvalidCapability(
                "non-revocation left bound: proof leaf hash does not match stamp",
            ));
        }
        if left.stamp >= witness.stamp {
            return Err(ArcError::InvalidCapability(
                "non-revocation left bound is not strictly less than target stamp",
            ));
        }
        if !verify_merkle_path(
            &left.stamp,
            &left.proof.sibling_hashes,
            left.proof.leaf_index,
            revocation_root,
        ) {
            return Err(ArcError::InvalidCapability(
                "non-revocation left bound Merkle proof invalid",
            ));
        }
    }

    if let Some(right) = &witness.right {
        if right.proof.leaf_hash != right.stamp {
            return Err(ArcError::InvalidCapability(
                "non-revocation right bound: proof leaf hash does not match stamp",
            ));
        }
        if right.stamp <= witness.stamp {
            return Err(ArcError::InvalidCapability(
                "non-revocation right bound is not strictly greater than target stamp",
            ));
        }
        if !verify_merkle_path(
            &right.stamp,
            &right.proof.sibling_hashes,
            right.proof.leaf_index,
            revocation_root,
        ) {
            return Err(ArcError::InvalidCapability(
                "non-revocation right bound Merkle proof invalid",
            ));
        }
    }

    match (&witness.left, &witness.right) {
        (None, None) => {
            // total_revoked > 0 but no bounds — invalid
            return Err(ArcError::InvalidCapability(
                "non-revocation witness has no bounds for non-empty revocation set",
            ));
        }
        (Some(left), None) => {
            // stamp > all revoked: left must be the last leaf.
            // Use expected_revocation_count (authenticated from AuthorityState), not
            // witness.total_revoked, to prevent a prover from forging the tree boundary.
            if left.proof.leaf_index != expected_revocation_count - 1 {
                return Err(ArcError::InvalidCapability(
                    "non-revocation left boundary is not the last leaf",
                ));
            }
        }
        (None, Some(right)) => {
            // stamp < all revoked: right must be the first leaf
            if right.proof.leaf_index != 0 {
                return Err(ArcError::InvalidCapability(
                    "non-revocation right boundary is not the first leaf",
                ));
            }
        }
        (Some(left), Some(right)) => {
            // stamp is between two adjacent leaves
            if left.proof.leaf_index + 1 != right.proof.leaf_index {
                return Err(ArcError::InvalidCapability(
                    "non-revocation boundaries are not adjacent leaves",
                ));
            }
        }
    }

    Ok(())
}

/// Verify the issuance proof for `cap` (spec §9 predicate point 7).
///
/// Verification chain:
/// 1. Verify `proof.epoch_cert` under `root_pk` — authenticates the epoch key.
/// 2. Verify `proof.sig` under the certified epoch key over the issuance
///    message.
///
/// `authority_root` and `epoch` must be the values at the time the capability
/// was issued.
pub fn verify_capability_issuance(
    cap: &Capability,
    authority_root: &[u8; 32],
    epoch: u64,
    proof: &CapabilityIssuanceProof,
    root_pk: &[u8; 32],
) -> Result<(), ArcError> {
    // Step 1: verify the cert chain so we know epoch_cert.epoch_pk is trusted.
    verify_epoch_cert(root_pk, &proof.epoch_cert)?;

    // Step 2: the issuance epoch must fall within the cert's validity window so
    // that an expired or future epoch key certificate cannot be (re-)used.
    let cert_epoch_end = proof.epoch_cert.epoch
        .saturating_add(proof.epoch_cert.validity_window);
    if epoch < proof.epoch_cert.epoch || epoch >= cert_epoch_end {
        return Err(ArcError::InvalidCapability(
            "capability issuance epoch is outside epoch cert validity window",
        ));
    }

    // Step 3: the issuance epoch must lie within the capability's own declared
    // valid epoch range, preventing issuance certs from being used outside the
    // capability's lifetime.
    if proof.epoch_cert.epoch < cap.epoch_start || proof.epoch_cert.epoch > cap.epoch_end {
        return Err(ArcError::InvalidCapability(
            "epoch cert epoch is outside capability validity range",
        ));
    }

    // Step 4: verify issuance signature under the authenticated epoch key.
    let epoch_pk = VerifyingKey::from_bytes(&proof.epoch_cert.epoch_pk)
        .map_err(|_| ArcError::InvalidCapability("invalid epoch public key in issuance proof"))?;

    let leaf_hash = capability_leaf_hash(cap);
    let msg = capability_issuance_signing_message(&leaf_hash, authority_root, epoch);
    let sig = Signature::from_bytes(&proof.sig);

    epoch_pk
        .verify_strict(&msg, &sig)
        .map_err(|_| ArcError::InvalidCapability("capability issuance signature invalid"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::rights::Rights;
    use super::super::authority::{AuthorityRootKeyPair, EpochSigningKeyPair};

    fn sample_cap(suffix: u8) -> Capability {
        Capability {
            subject: format!("subject-{suffix}"),
            object_id: "doc.pdf".to_string(),
            rights: Rights::READ,
            policy_hash: [suffix; 32],
            epoch_start: 1,
            epoch_end: 100,
            delegation_depth: 0,
            nonce: [suffix; 16],
        }
    }

    fn sample_state(epoch: u64, tree: &AuthorityCapabilityTree) -> AuthorityState {
        AuthorityState {
            authority_root: tree.authority_root(),
            revocation_root: tree.revocation_root(),
            transparency_root: [0u8; 32],
            epoch,
            authority_id: "auth-test".to_string(),
            epoch_signature_valid: true,
            epoch_key_cert_valid: true,
            transparency_inclusion_valid: true,
            root_pk: [0u8; 32],
            revocation_count: tree.revocation_count(),
        }
    }

    // -----------------------------------------------------------------------
    // AuthorityCapabilityTree — structure and roots
    // -----------------------------------------------------------------------

    #[test]
    fn single_capability_root_equals_leaf_hash() {
        let cap = sample_cap(1);
        let mut tree = AuthorityCapabilityTree::new();
        let leaf = tree.add_capability(&cap);

        // For a single-leaf Merkle tree, root == leaf.
        assert_eq!(tree.authority_root(), leaf);
        assert_eq!(tree.authority_root(), capability_leaf_hash(&cap));
    }

    #[test]
    fn adding_same_capability_twice_is_idempotent() {
        let cap = sample_cap(2);
        let mut tree = AuthorityCapabilityTree::new();
        tree.add_capability(&cap);
        tree.add_capability(&cap);

        assert_eq!(tree.len(), 1);
    }

    #[test]
    fn authority_root_changes_when_capability_added() {
        let cap1 = sample_cap(3);
        let cap2 = sample_cap(4);
        let mut tree = AuthorityCapabilityTree::new();
        tree.add_capability(&cap1);
        let root_after_one = tree.authority_root();

        tree.add_capability(&cap2);
        let root_after_two = tree.authority_root();

        assert_ne!(root_after_one, root_after_two);
    }

    #[test]
    fn revocation_root_changes_when_stamp_added() {
        let cap = sample_cap(5);
        let mut tree = AuthorityCapabilityTree::new();
        tree.add_capability(&cap);

        let state = sample_state(10, &tree);
        let empty_rev_root = tree.revocation_root();

        tree.revoke_capability(&cap, &state);
        assert_ne!(tree.revocation_root(), empty_rev_root);
    }

    #[test]
    fn is_revoked_detects_revoked_stamp() {
        let cap = sample_cap(6);
        let mut tree = AuthorityCapabilityTree::new();
        tree.add_capability(&cap);
        let state = sample_state(10, &tree);
        let stamp = capability_stamp(&cap, &state);

        assert!(!tree.is_revoked(&stamp));
        tree.revoke_stamp(stamp);
        assert!(tree.is_revoked(&stamp));
    }

    // -----------------------------------------------------------------------
    // Merkle inclusion proofs
    // -----------------------------------------------------------------------

    #[test]
    fn inclusion_proof_verifies_for_single_cap() {
        let cap = sample_cap(7);
        let mut tree = AuthorityCapabilityTree::new();
        tree.add_capability(&cap);
        let root = tree.authority_root();

        let proof = tree.inclusion_proof(&cap).expect("cap should be in tree");
        verify_capability_inclusion(&cap, &proof, &root).expect("proof should verify");
    }

    #[test]
    fn inclusion_proof_verifies_for_multiple_caps() {
        let caps: Vec<Capability> = (10..18).map(sample_cap).collect();
        let mut tree = AuthorityCapabilityTree::new();
        for cap in &caps {
            tree.add_capability(cap);
        }
        let root = tree.authority_root();

        for cap in &caps {
            let proof = tree.inclusion_proof(cap).expect("cap should be in tree");
            verify_capability_inclusion(cap, &proof, &root)
                .expect("every cap should have a valid proof");
        }
    }

    #[test]
    fn inclusion_proof_rejects_wrong_root() {
        let cap = sample_cap(20);
        let mut tree = AuthorityCapabilityTree::new();
        tree.add_capability(&cap);
        let proof = tree.inclusion_proof(&cap).unwrap();

        let wrong_root = [0xFFu8; 32];
        let err = verify_capability_inclusion(&cap, &proof, &wrong_root)
            .expect_err("wrong root should be rejected");
        assert!(matches!(
            err,
            ArcError::InvalidCapability("capability Merkle inclusion proof root mismatch")
        ));
    }

    #[test]
    fn inclusion_proof_rejects_tampered_leaf() {
        let cap = sample_cap(21);
        let mut tree = AuthorityCapabilityTree::new();
        tree.add_capability(&cap);
        let root = tree.authority_root();
        let mut proof = tree.inclusion_proof(&cap).unwrap();
        proof.leaf_hash[0] ^= 0xFF; // tamper

        let err = verify_capability_inclusion(&cap, &proof, &root)
            .expect_err("tampered leaf hash should be rejected");
        assert!(matches!(
            err,
            ArcError::InvalidCapability("inclusion proof leaf hash does not match capability")
        ));
    }

    #[test]
    fn inclusion_proof_returns_none_for_absent_cap() {
        let cap = sample_cap(30);
        let other = sample_cap(31);
        let mut tree = AuthorityCapabilityTree::new();
        tree.add_capability(&other);

        assert!(tree.inclusion_proof(&cap).is_none());
    }

    // -----------------------------------------------------------------------
    // Capability issuance signatures (spec §9 point 7)
    // -----------------------------------------------------------------------

    fn make_keypairs() -> (AuthorityRootKeyPair, EpochSigningKeyPair) {
        use rand::rngs::OsRng;
        (
            AuthorityRootKeyPair::generate(&mut OsRng),
            EpochSigningKeyPair::generate(&mut OsRng),
        )
    }

    fn issue_cap(
        cap: &Capability,
        tree: &AuthorityCapabilityTree,
        epoch: u64,
        root_kp: &AuthorityRootKeyPair,
        epoch_kp: &EpochSigningKeyPair,
    ) -> CapabilityIssuanceProof {
        let authority_root = tree.authority_root();
        let leaf_hash = capability_leaf_hash(cap);
        let sig = epoch_kp.sign_capability_issuance(&leaf_hash, &authority_root, epoch);
        let epoch_cert = root_kp.issue_epoch_cert(&epoch_kp.verifying_key_bytes(), epoch, 10);
        CapabilityIssuanceProof { sig, epoch_cert }
    }

    #[test]
    fn capability_issuance_proof_verifies() {
        let cap = sample_cap(40);
        let mut tree = AuthorityCapabilityTree::new();
        tree.add_capability(&cap);
        let (root_kp, epoch_kp) = make_keypairs();
        let proof = issue_cap(&cap, &tree, 42, &root_kp, &epoch_kp);

        verify_capability_issuance(
            &cap,
            &tree.authority_root(),
            42,
            &proof,
            &root_kp.verifying_key_bytes(),
        )
        .expect("valid issuance proof should verify");
    }

    #[test]
    fn capability_issuance_proof_rejects_tampered_capability() {
        let cap = sample_cap(41);
        let mut tampered = cap.clone();
        tampered.rights = Rights::WRITE; // different rights

        let mut tree = AuthorityCapabilityTree::new();
        tree.add_capability(&cap);
        let (root_kp, epoch_kp) = make_keypairs();
        let proof = issue_cap(&cap, &tree, 42, &root_kp, &epoch_kp);

        // Verify with the tampered cap (different leaf hash)
        let err = verify_capability_issuance(
            &tampered,
            &tree.authority_root(),
            42,
            &proof,
            &root_kp.verifying_key_bytes(),
        )
        .expect_err("tampered capability should be rejected");
        assert!(matches!(
            err,
            ArcError::InvalidCapability("capability issuance signature invalid")
        ));
    }

    #[test]
    fn capability_issuance_proof_rejects_wrong_root_pk() {
        let cap = sample_cap(42);
        let mut tree = AuthorityCapabilityTree::new();
        tree.add_capability(&cap);
        let (root_kp, epoch_kp) = make_keypairs();
        let (wrong_root, _) = make_keypairs();
        let proof = issue_cap(&cap, &tree, 42, &root_kp, &epoch_kp);

        let err = verify_capability_issuance(
            &cap,
            &tree.authority_root(),
            42,
            &proof,
            &wrong_root.verifying_key_bytes(), // wrong trust anchor
        )
        .expect_err("wrong root pk should be rejected");
        assert!(matches!(
            err,
            ArcError::AuthorityState("epoch key certificate signature invalid")
        ));
    }

    #[test]
    fn capability_issuance_proof_rejects_wrong_epoch() {
        let cap = sample_cap(43);
        let mut tree = AuthorityCapabilityTree::new();
        tree.add_capability(&cap);
        let (root_kp, epoch_kp) = make_keypairs();
        let proof = issue_cap(&cap, &tree, 42, &root_kp, &epoch_kp);

        // Attempt to verify against a different epoch
        let err = verify_capability_issuance(
            &cap,
            &tree.authority_root(),
            99, // different epoch from what was signed
            &proof,
            &root_kp.verifying_key_bytes(),
        )
        .expect_err("wrong epoch should be rejected");
        // With validity window enforcement, the epoch-out-of-window check fires
        // before the signature check, so the error message changed.
        assert!(matches!(
            err,
            ArcError::InvalidCapability("capability issuance epoch is outside epoch cert validity window")
        ));
    }

    // -----------------------------------------------------------------------
    // Non-revocation witnesses (spec §9 point 2)
    // -----------------------------------------------------------------------

    /// Build a tree with `n` revoked stamps derived from the given seeds and
    /// return the tree + one non-revoked stamp for the caller to test with.
    fn revocation_tree(revoked_seeds: &[u8]) -> AuthorityCapabilityTree {
        let mut tree = AuthorityCapabilityTree::new();
        for &s in revoked_seeds {
            tree.revoke_stamp([s; 32]);
        }
        tree
    }

    #[test]
    fn non_revocation_witness_empty_set() {
        let tree = AuthorityCapabilityTree::new();
        let stamp = [0x42u8; 32];
        let witness = tree.non_revocation_witness(&stamp).expect("empty set always succeeds");
        assert_eq!(witness.total_revoked, 0);
        assert!(witness.left.is_none());
        assert!(witness.right.is_none());

        verify_non_revocation(&witness, &tree.revocation_root(), tree.revocation_count())
            .expect("empty-set witness must verify");
    }

    #[test]
    fn non_revocation_witness_stamp_is_revoked_returns_err() {
        let mut tree = AuthorityCapabilityTree::new();
        let stamp = [0x55u8; 32];
        tree.revoke_stamp(stamp);
        let err = tree.non_revocation_witness(&stamp)
            .expect_err("revoked stamp must return Err");
        assert!(matches!(err, ArcError::InvalidCapability(_)));
    }

    #[test]
    fn non_revocation_witness_stamp_smaller_than_all() {
        // Revoke stamps 0x10..0x14 so stamp 0x01 is below all.
        let tree = revocation_tree(&[0x10, 0x11, 0x12, 0x13]);
        let stamp = [0x01u8; 32];
        let witness = tree.non_revocation_witness(&stamp).unwrap();

        assert!(witness.left.is_none(), "nothing to the left");
        assert!(witness.right.is_some(), "right boundary must exist");
        // right must be the first (smallest) leaf
        assert_eq!(witness.right.as_ref().unwrap().proof.leaf_index, 0);

        let rev_root = tree.revocation_root();
        verify_non_revocation(&witness, &rev_root, tree.revocation_count()).expect("witness must verify");
    }

    #[test]
    fn non_revocation_witness_stamp_larger_than_all() {
        let tree = revocation_tree(&[0x10, 0x11, 0x12, 0x13]);
        let stamp = [0xFFu8; 32];
        let witness = tree.non_revocation_witness(&stamp).unwrap();

        assert!(witness.right.is_none(), "nothing to the right");
        assert!(witness.left.is_some(), "left boundary must exist");
        // left must be the last (largest) leaf
        assert_eq!(
            witness.left.as_ref().unwrap().proof.leaf_index,
            witness.total_revoked - 1
        );

        verify_non_revocation(&witness, &tree.revocation_root(), tree.revocation_count()).expect("witness must verify");
    }

    #[test]
    fn non_revocation_witness_stamp_between_two_elements() {
        // Revoke 0x10 and 0x30 so 0x20 falls between them.
        let tree = revocation_tree(&[0x10, 0x30]);
        let stamp = [0x20u8; 32];
        let witness = tree.non_revocation_witness(&stamp).unwrap();

        let left = witness.left.as_ref().expect("left must exist");
        let right = witness.right.as_ref().expect("right must exist");
        assert_eq!(left.proof.leaf_index + 1, right.proof.leaf_index, "must be adjacent");

        verify_non_revocation(&witness, &tree.revocation_root(), tree.revocation_count()).expect("witness must verify");
    }

    #[test]
    fn non_revocation_witness_eight_stamps_every_position() {
        // Revoke even byte values 0x02,0x04,...0x10 (8 stamps).
        let revoked: Vec<u8> = (1u8..=8).map(|i| i * 2).collect();
        let tree = revocation_tree(&revoked);
        let rev_root = tree.revocation_root();

        // Prove non-revocation for odd stamps that fall between the revoked ones.
        for odd in [0x01u8, 0x03, 0x05, 0x07, 0x09, 0x0B, 0x0D, 0x0F, 0x11] {
            let stamp = [odd; 32];
            let witness = tree.non_revocation_witness(&stamp)
                .unwrap_or_else(|_| panic!("non-revocation witness for 0x{odd:02x} should succeed"));
            verify_non_revocation(&witness, &rev_root, tree.revocation_count())
                .unwrap_or_else(|e| panic!("witness for 0x{odd:02x} failed: {e:?}"));
        }
    }

    #[test]
    fn verify_non_revocation_rejects_tampered_left_stamp() {
        let tree = revocation_tree(&[0x10, 0x30]);
        let stamp = [0x20u8; 32];
        let mut witness = tree.non_revocation_witness(&stamp).unwrap();
        // Tamper: change the left boundary stamp to something that makes it
        // look like the stamp is actually == to the left (breaks ordering).
        if let Some(ref mut left) = witness.left {
            left.stamp = witness.stamp; // no longer strictly less
        }
        let err = verify_non_revocation(&witness, &tree.revocation_root(), tree.revocation_count())
            .expect_err("tampered left stamp ordering must be rejected");
        assert!(matches!(err, ArcError::InvalidCapability(_)));
    }

    #[test]
    fn verify_non_revocation_rejects_wrong_revocation_root() {
        let tree = revocation_tree(&[0x10, 0x20, 0x30]);
        let stamp = [0x15u8; 32];
        let witness = tree.non_revocation_witness(&stamp).unwrap();

        let wrong_root = [0xFFu8; 32];
        let err = verify_non_revocation(&witness, &wrong_root, tree.revocation_count())
            .expect_err("wrong revocation root must be rejected");
        assert!(matches!(err, ArcError::InvalidCapability(_)));
    }
}
