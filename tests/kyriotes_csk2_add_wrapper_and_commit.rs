/// Integration tests for `add_epoch_wrapper_and_commit` — atomically commits
/// `to_state` to the transparency log and adds a re-wrap epoch wrapper.
mod helpers;

use helpers::scenario::Scenario;
use helpers::transparency::commit_state;
use kyriotes_csk2::{
    InMemoryTransparencyLog, KyriotesCsk2Error, StubAuthorityVerifier, TemporalPolicy,
    add_epoch_wrapper_and_commit, open, seal,
};

// ---------------------------------------------------------------------------
// Happy path: committed proof is baked into the wrapper
// ---------------------------------------------------------------------------

/// The wrapper added by `add_epoch_wrapper_and_commit` must carry the
/// transparency proof that was produced by the log commit, not a zero-root.
#[test]
fn add_epoch_wrapper_and_commit_bakes_in_committed_proof() {
    let s = Scenario::baseline("aewac-proof", 42)
        .with_temporal_policy(TemporalPolicy::Current)
        .with_message(b"rewrap payload");

    let mut obj = seal(
        &s.keypair.public,
        &s.message,
        &s.cap,
        &s.proof,
        &s.seal_transparency_proof,
        &s.seal_state,
        &s.req,
        s.temporal_policy.clone(),
    )
    .expect("initial seal should succeed");

    let mut log = InMemoryTransparencyLog::new();
    let seed50 = s.make_state_at_epoch(50);
    let verifier = StubAuthorityVerifier;

    let commit = add_epoch_wrapper_and_commit(
        &mut log,
        &verifier,
        &s.keypair.secret,
        &s.keypair.public,
        &mut obj,
        &s.cap,
        &s.proof, // proof is for from_state (epoch 42)
        &s.seal_state,
        &seed50,
    )
    .expect("add_epoch_wrapper_and_commit should succeed");

    // The commit must have a real (non-zero) transparency root.
    assert_ne!(
        commit.state.transparency_root, [0u8; 32],
        "committed state must have real transparency root"
    );

    // The new wrapper must carry the proof returned by the commit.
    let wrapper50 = obj
        .wrappers
        .iter()
        .find(|w| w.epoch == 50)
        .expect("wrapper at epoch 50 must exist");
    assert_eq!(
        wrapper50.transparency_proof.leaf_hash, commit.proof.leaf_hash,
        "wrapper must carry the committed transparency proof"
    );
}

// ---------------------------------------------------------------------------
// Happy path: object is openable at the new epoch
// ---------------------------------------------------------------------------

/// After `add_epoch_wrapper_and_commit`, the object must be openable at the
/// new epoch using the state and proof from the commit.
#[test]
fn add_epoch_wrapper_and_commit_object_is_openable_at_new_epoch() {
    let s = Scenario::baseline("aewac-open", 42)
        .with_temporal_policy(TemporalPolicy::Current)
        .with_message(b"secret for epoch 50");

    let mut obj = seal(
        &s.keypair.public,
        &s.message,
        &s.cap,
        &s.proof,
        &s.seal_transparency_proof,
        &s.seal_state,
        &s.req,
        s.temporal_policy.clone(),
    )
    .expect("initial seal should succeed");

    let mut log = InMemoryTransparencyLog::new();
    let seed50 = s.make_state_at_epoch(50);
    let verifier = StubAuthorityVerifier;

    let commit = add_epoch_wrapper_and_commit(
        &mut log,
        &verifier,
        &s.keypair.secret,
        &s.keypair.public,
        &mut obj,
        &s.cap,
        &s.proof, // proof is for from_state (epoch 42)
        &s.seal_state,
        &seed50,
    )
    .expect("add_epoch_wrapper_and_commit should succeed");

    // Open using the committed state and proof.
    let proof_at_50 = s.build_proof_for_state(&commit.state);
    let plaintext = open(&s.keypair.secret, &obj, &s.cap, &proof_at_50, &commit.state)
        .expect("open at epoch 50 should succeed");

    assert_eq!(plaintext, b"secret for epoch 50");
}

// ---------------------------------------------------------------------------
// Error path: from-epoch wrapper missing
// ---------------------------------------------------------------------------

/// `add_epoch_wrapper_and_commit` returns `MissingWrapper` when the
/// from-state epoch has no wrapper in the object.
#[test]
fn add_epoch_wrapper_and_commit_rejects_missing_from_wrapper() {
    let s = Scenario::baseline("aewac-missing", 42).with_temporal_policy(TemporalPolicy::Current);

    let mut obj = seal(
        &s.keypair.public,
        &s.message,
        &s.cap,
        &s.proof,
        &s.seal_transparency_proof,
        &s.seal_state,
        &s.req,
        s.temporal_policy.clone(),
    )
    .expect("initial seal should succeed");

    // Commit a state at epoch 50 to use as from_state (no wrapper there).
    let mut log_pre = InMemoryTransparencyLog::new();
    let seed50 = s.make_state_at_epoch(50);
    let (state50, _) = commit_state(&mut log_pre, &seed50).expect("commit epoch 50");
    let proof50 = s.build_proof_for_state(&state50);

    let seed55 = s.make_state_at_epoch(55);
    let verifier = StubAuthorityVerifier;
    let mut log = InMemoryTransparencyLog::new();

    // from_state = epoch 50 (no wrapper); to_state = epoch 55
    let err = add_epoch_wrapper_and_commit(
        &mut log,
        &verifier,
        &s.keypair.secret,
        &s.keypair.public,
        &mut obj,
        &s.cap,
        &proof50,
        &state50, // from_state at epoch 50 — no wrapper exists
        &seed55,
    )
    .expect_err("should fail with MissingWrapper");

    assert!(
        matches!(err, KyriotesCsk2Error::MissingWrapper),
        "expected MissingWrapper, got {err:?}"
    );
}
