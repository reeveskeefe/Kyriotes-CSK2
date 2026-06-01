mod helpers;

use helpers::scenario::Scenario;
use kyriotes_csk2::{
    AuthorityCapabilityTree, AuthorityState, InMemoryTransparencyLog, KyriotesCsk2Error,
    TransparencyLog, capability_stamp, revoke_capability, revoke_capability_and_commit,
};

#[test]
fn revoke_capability_and_commit_updates_roots_and_log() {
    let s = Scenario::baseline("strict", 42);

    let mut tree = AuthorityCapabilityTree::new();
    tree.add_capability(&s.cap);

    let mut log = InMemoryTransparencyLog::new();
    log.commit_state(&s.seal_state).expect("base state commit");

    let commit = revoke_capability_and_commit(&mut log, &mut tree, &s.cap, &s.seal_state, 43)
        .expect("revocation commit should succeed");

    assert_eq!(commit.state.epoch, 43);
    assert_eq!(commit.state.authority_root, s.seal_state.authority_root);
    assert_ne!(commit.state.revocation_root, s.seal_state.revocation_root);

    let revoked_stamp = capability_stamp(&s.cap, &commit.state);
    assert!(tree.is_revoked(&revoked_stamp));

    let roundtrip_proof = log
        .proof_for_state(&commit.state)
        .expect("revoked state must be in transparency log");
    assert_eq!(roundtrip_proof.leaf_hash, commit.proof.leaf_hash);
}

#[test]
fn revoke_capability_rejects_state_tree_root_mismatch() {
    let s = Scenario::baseline("strict", 42);

    let mut tree = AuthorityCapabilityTree::new();
    tree.add_capability(&s.cap);

    let mut bad_state = s.seal_state.clone();
    bad_state.revocation_root = [9u8; 32];

    let err = revoke_capability(&mut tree, &s.cap, &bad_state, 43)
        .expect_err("revocation should fail when state roots are stale");

    assert!(matches!(
        err,
        KyriotesCsk2Error::AuthorityState("revocation root does not match capability tree")
    ));
}

#[test]
fn revoked_stamp_cannot_get_non_revocation_witness() {
    let s = Scenario::baseline("strict", 42);

    let mut tree = AuthorityCapabilityTree::new();
    tree.add_capability(&s.cap);

    let revoked_state = revoke_capability(&mut tree, &s.cap, &s.seal_state, 43)
        .expect("revocation state derivation should succeed");

    let revoked_stamp = capability_stamp(&s.cap, &revoked_state);
    let err = tree
        .non_revocation_witness(&revoked_stamp)
        .expect_err("revoked stamp must not have a non-revocation witness");

    assert!(matches!(
        err,
        KyriotesCsk2Error::InvalidCapability(
            "capability is revoked; no non-revocation witness possible"
        )
    ));
}

/// V7 regression: capability_stamp must be epoch-independent so that a
/// revocation committed at epoch e_r remains detectable at every later epoch.
/// Before the fix, stamp-v1 embedded `state.epoch` and `state.authority_root`,
/// causing the stamp to silently change on every epoch rotation and bypass the
/// revocation set.
#[test]
fn revocation_persists_after_epoch_rotation() {
    let s = Scenario::baseline("strict", 42);

    let mut tree = AuthorityCapabilityTree::new();
    tree.add_capability(&s.cap);

    // Revoke at epoch 43.
    let revoked_state =
        revoke_capability(&mut tree, &s.cap, &s.seal_state, 43).expect("revocation should succeed");

    // Simulate epoch rotation to epoch 44: authority_root and revocation_root
    // are carried forward unchanged (as rotate_epoch does), only epoch advances.
    let state_44 = AuthorityState {
        epoch: 44,
        ..revoked_state.clone()
    };

    // The stamp at epoch 44 must equal the stamp at epoch 43 (epoch-independent)
    // and must still be found in the revocation set.
    let stamp_43 = capability_stamp(&s.cap, &revoked_state);
    let stamp_44 = capability_stamp(&s.cap, &state_44);
    assert_eq!(
        stamp_43, stamp_44,
        "stamp must be stable across epoch rotation"
    );
    assert!(
        tree.is_revoked(&stamp_44),
        "revocation must persist after epoch rotation"
    );
}
