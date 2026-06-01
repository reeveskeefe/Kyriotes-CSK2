/// Integration tests for spec §2 Issue: `issue_capability` and
/// `issue_capability_and_commit`.
mod helpers;

use helpers::{
    capability::sample_cap,
    request_builders::{policy_hash, sample_req},
};
use kyriotes_csk2::{
    AuthorityCapabilityTree, AuthorityRootKeyPair, AuthorityState, EpochSigningKeyPair,
    InMemoryTransparencyLog, KyriotesCsk2Error, hash_policy, issue_capability,
    issue_capability_and_commit, open, seal, verify_capability_issuance,
};

// ---------------------------------------------------------------------------
// issue_capability
// ---------------------------------------------------------------------------

#[test]
fn issue_capability_adds_cap_to_tree_and_returns_valid_proof() {
    let p = policy_hash("test");
    let cap = sample_cap(40, 60, p);
    let mut rng = rand::rngs::OsRng;
    let root_kp = AuthorityRootKeyPair::generate(&mut rng);
    let epoch_kp = EpochSigningKeyPair::generate(&mut rng);
    let epoch_cert = root_kp.issue_epoch_cert(&epoch_kp.verifying_key_bytes(), 42, 10);
    let mut tree = AuthorityCapabilityTree::new();

    let proof = issue_capability(&mut tree, &cap, &epoch_kp, &epoch_cert)
        .expect("issue_capability should succeed");

    // Tree must now contain the cap.
    assert!(
        tree.inclusion_proof(&cap).is_some(),
        "cap must be in tree after issue"
    );

    // The returned issuance proof must verify.
    verify_capability_issuance(
        &cap,
        &tree.authority_root(),
        proof.epoch_cert.epoch,
        &proof,
        &root_kp.verifying_key_bytes(),
    )
    .expect("issuance proof must verify");
}

#[test]
fn issue_capability_is_idempotent_for_same_cap() {
    let p = policy_hash("idempotent");
    let cap = sample_cap(40, 60, p);
    let mut rng = rand::rngs::OsRng;
    let root_kp = AuthorityRootKeyPair::generate(&mut rng);
    let epoch_kp = EpochSigningKeyPair::generate(&mut rng);
    let epoch_cert = root_kp.issue_epoch_cert(&epoch_kp.verifying_key_bytes(), 42, 10);
    let mut tree = AuthorityCapabilityTree::new();

    issue_capability(&mut tree, &cap, &epoch_kp, &epoch_cert).unwrap();
    let root_first = tree.authority_root();

    // Issue again — tree root must be unchanged.
    issue_capability(&mut tree, &cap, &epoch_kp, &epoch_cert).unwrap();
    assert_eq!(
        tree.authority_root(),
        root_first,
        "issuing the same cap twice must not change the root"
    );
}

#[test]
fn issue_capability_rejects_cert_epoch_before_cap_range() {
    let p = policy_hash("before");
    let cap = sample_cap(40, 60, p);
    let mut rng = rand::rngs::OsRng;
    let root_kp = AuthorityRootKeyPair::generate(&mut rng);
    let epoch_kp = EpochSigningKeyPair::generate(&mut rng);
    // cert epoch 5 < cap.epoch_start 40
    let epoch_cert = root_kp.issue_epoch_cert(&epoch_kp.verifying_key_bytes(), 5, 10);
    let mut tree = AuthorityCapabilityTree::new();

    let err = issue_capability(&mut tree, &cap, &epoch_kp, &epoch_cert)
        .expect_err("cert epoch before cap range should fail");
    assert!(matches!(err, KyriotesCsk2Error::InvalidCapability(_)));
}

#[test]
fn issue_capability_rejects_cert_epoch_after_cap_range() {
    let p = policy_hash("after");
    let cap = sample_cap(40, 60, p);
    let mut rng = rand::rngs::OsRng;
    let root_kp = AuthorityRootKeyPair::generate(&mut rng);
    let epoch_kp = EpochSigningKeyPair::generate(&mut rng);
    // cert epoch 99 > cap.epoch_end 60
    let epoch_cert = root_kp.issue_epoch_cert(&epoch_kp.verifying_key_bytes(), 99, 10);
    let mut tree = AuthorityCapabilityTree::new();

    let err = issue_capability(&mut tree, &cap, &epoch_kp, &epoch_cert)
        .expect_err("cert epoch after cap range should fail");
    assert!(matches!(err, KyriotesCsk2Error::InvalidCapability(_)));
}

// ---------------------------------------------------------------------------
// issue_capability_and_commit
// ---------------------------------------------------------------------------

#[test]
fn issue_capability_and_commit_produces_usable_seal_state() {
    let p = policy_hash("commit-flow");
    let cap = sample_cap(40, 60, p);
    let mut rng = rand::rngs::OsRng;
    let root_kp = AuthorityRootKeyPair::generate(&mut rng);
    let epoch_kp = EpochSigningKeyPair::generate(&mut rng);
    let epoch_cert = root_kp.issue_epoch_cert(&epoch_kp.verifying_key_bytes(), 42, 10);
    let mut tree = AuthorityCapabilityTree::new();
    let mut log = InMemoryTransparencyLog::new();

    // Build the base_state snapshot from the empty tree (no pre-commit needed;
    // issue_capability_and_commit will perform the first and only commit).
    let base_state = AuthorityState {
        authority_root: tree.authority_root(),
        revocation_root: tree.revocation_root(),
        transparency_root: [0u8; 32], // will be filled by commit
        epoch: 42,
        authority_id: "auth-main".to_string(),
        root_pk: root_kp.verifying_key_bytes(),
        revocation_count: tree.revocation_count(),
        prev_epoch_hash: [0u8; 32],
    };

    let (issuance_proof, commit) = issue_capability_and_commit(
        &mut log,
        &mut tree,
        &cap,
        &epoch_kp,
        &epoch_cert,
        &base_state,
    )
    .expect("issue_capability_and_commit should succeed");

    // The committed state should have the updated authority_root.
    assert_ne!(
        commit.state.authority_root, [0u8; 32],
        "committed authority root must not be zero"
    );
    assert_ne!(
        commit.state.transparency_root, [0u8; 32],
        "committed transparency root must be set"
    );

    // Build a full CapabilityProof and seal/open to confirm the proof works.
    use kyriotes_csk2::{CapabilityProof, RecipientKeyPair, capability_stamp};
    let state = &commit.state;
    let inclusion = tree.inclusion_proof(&cap).expect("cap must be in tree");
    let stamp = capability_stamp(&cap, state);
    let non_revocation = tree
        .non_revocation_witness(&stamp)
        .expect("must not be revoked");
    let proof = CapabilityProof {
        inclusion,
        non_revocation,
        issuance: issuance_proof,
    };

    let req = sample_req(42, p);
    let keypair = RecipientKeyPair::generate(&mut rng);

    let obj = seal(
        &keypair.public,
        b"hello",
        &cap,
        &proof,
        &commit.proof,
        state,
        &req,
        kyriotes_csk2::TemporalPolicy::Historical(42),
    )
    .expect("seal should succeed");

    let plaintext = open(&keypair.secret, &obj, &cap, &proof, state).expect("open should succeed");
    assert_eq!(plaintext, b"hello");
}

#[test]
fn issue_capability_and_commit_rejects_stale_base_state() {
    let p = policy_hash("stale");
    let cap = sample_cap(40, 60, p);
    let mut rng = rand::rngs::OsRng;
    let root_kp = AuthorityRootKeyPair::generate(&mut rng);
    let epoch_kp = EpochSigningKeyPair::generate(&mut rng);
    let epoch_cert = root_kp.issue_epoch_cert(&epoch_kp.verifying_key_bytes(), 42, 10);
    let mut tree = AuthorityCapabilityTree::new();
    let mut log = InMemoryTransparencyLog::new();

    // Pre-add a different cap to the tree so the root diverges from base_state.
    let other_cap = sample_cap(1, 100, hash_policy("other"));
    tree.add_capability(&other_cap);

    // base_state has an empty tree root — mismatch.
    let base_state = AuthorityState {
        authority_root: [0u8; 32], // deliberately wrong
        revocation_root: tree.revocation_root(),
        transparency_root: [0u8; 32],
        epoch: 42,
        authority_id: "auth-main".to_string(),
        root_pk: root_kp.verifying_key_bytes(),
        revocation_count: 0,
        prev_epoch_hash: [0u8; 32],
    };

    let err = issue_capability_and_commit(
        &mut log,
        &mut tree,
        &cap,
        &epoch_kp,
        &epoch_cert,
        &base_state,
    )
    .expect_err("stale base state should be rejected");
    assert!(matches!(err, KyriotesCsk2Error::AuthorityState(_)));
}
