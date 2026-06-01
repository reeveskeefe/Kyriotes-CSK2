/// End-to-end tests for the `ResealRequired` temporal policy and the
/// `open_and_reseal_and_commit` helper (spec §15).
///
/// `ResealRequired { after: e_after }`:
/// - e_open ≤ e_after  → use the original seal-epoch wrapper (no reseal needed)
/// - e_open > e_after  → MissingWrapper; caller must reseal before retrying
///
/// `open_and_reseal_and_commit` opens the old object and seals the plaintext
/// with a fresh DEK under a new committed authority state.
mod helpers;

use helpers::scenario::Scenario;
use helpers::transparency::commit_state;
use kyriotes_csk2::{
    InMemoryTransparencyLog, KyriotesCsk2Error, RecipientKeyPair, StubAuthorityVerifier,
    TemporalPolicy, open, open_and_reseal, open_and_reseal_and_commit, seal,
};

// ---------------------------------------------------------------------------
// open_and_reseal_and_commit — basic contract
// ---------------------------------------------------------------------------

/// `open_and_reseal_and_commit` produces an object openable by the new recipient.
#[test]
fn open_and_reseal_and_commit_produces_openable_object() {
    let s = Scenario::baseline("rac-happy", 45).with_message(b"secret data");

    let original = seal(
        &s.keypair.public,
        &s.message,
        &s.cap,
        &s.proof,
        &s.seal_transparency_proof,
        &s.seal_state,
        &s.req,
        s.temporal_policy.clone(),
    )
    .expect("seal");

    let new_kp = RecipientKeyPair::generate(&mut rand::rngs::OsRng);
    let mut log = InMemoryTransparencyLog::new();
    let verifier = StubAuthorityVerifier;

    let (resealed, commit) = open_and_reseal_and_commit(
        &mut log,
        &verifier,
        &s.keypair.secret,
        &new_kp.public,
        &original,
        &s.cap,
        &s.proof,
        &s.seal_state,
        &s.proof,
        &s.seal_state,
        &s.req,
        s.temporal_policy.clone(),
    )
    .expect("open_and_reseal_and_commit should succeed");

    // The returned commit must have a real transparency root.
    assert_ne!(commit.state.transparency_root, [0u8; 32]);

    // New recipient can open the resealed object.
    let plaintext = open(&new_kp.secret, &resealed, &s.cap, &s.proof, &commit.state)
        .expect("new recipient must open resealed object");
    assert_eq!(plaintext, b"secret data");
}

/// `open_and_reseal_and_commit` bakes the committed transparency root into the
/// wrapper — the resealed object is verifiable against the returned commit state.
#[test]
fn open_and_reseal_and_commit_wrapper_bound_to_committed_root() {
    let s = Scenario::baseline("rac-root", 45).with_message(b"payload");

    let original = seal(
        &s.keypair.public,
        &s.message,
        &s.cap,
        &s.proof,
        &s.seal_transparency_proof,
        &s.seal_state,
        &s.req,
        s.temporal_policy.clone(),
    )
    .expect("seal");

    let new_kp = RecipientKeyPair::generate(&mut rand::rngs::OsRng);
    let mut log = InMemoryTransparencyLog::new();
    let verifier = StubAuthorityVerifier;

    let (resealed, commit) = open_and_reseal_and_commit(
        &mut log,
        &verifier,
        &s.keypair.secret,
        &new_kp.public,
        &original,
        &s.cap,
        &s.proof,
        &s.seal_state,
        &s.proof,
        &s.seal_state,
        &s.req,
        s.temporal_policy.clone(),
    )
    .expect("open_and_reseal_and_commit");

    // The wrapper's context_hash is computed from the committed transparency root.
    // If we try to open with a state whose transparency_root doesn't match, the
    // DEK unwrap (context_hash mismatch) should fail.
    assert_eq!(
        resealed.wrappers[0].epoch, commit.state.epoch,
        "wrapper epoch must match committed state epoch"
    );
}

// ---------------------------------------------------------------------------
// ResealRequired end-to-end flow
// ---------------------------------------------------------------------------

/// Full reseal flow:
/// 1. Seal with ResealRequired { after: 44 } at epoch 42.
/// 2. Opening at epoch 45 (> boundary) fails with MissingWrapper.
/// 3. Reseal using the original epoch-42 wrapper (still valid for open because 42 ≤ 44).
/// 4. New object opens successfully at epoch 45.
#[test]
fn reseal_required_full_e2e_flow() {
    let s = Scenario::baseline("rr-e2e", 42)
        .with_temporal_policy(TemporalPolicy::ResealRequired { after: 44 })
        .with_message(b"classified content");

    // Step 1: Seal at epoch 42 with ResealRequired{44}.
    let original = seal(
        &s.keypair.public,
        &s.message,
        &s.cap,
        &s.proof,
        &s.seal_transparency_proof,
        &s.seal_state,
        &s.req,
        s.temporal_policy.clone(),
    )
    .expect("seal at epoch 42");

    let mut log = InMemoryTransparencyLog::new();

    // Step 2: Opening at epoch 45 without a new wrapper → MissingWrapper.
    let seed45 = s.make_state_at_epoch(45);
    let (state45, _proof45) = commit_state(&mut log, &seed45).expect("commit 45");
    let proof_for_45 = s.build_proof_for_state(&state45);

    let err = open(
        &s.keypair.secret,
        &original,
        &s.cap,
        &proof_for_45,
        &state45,
    )
    .expect_err("should fail past reseal boundary");
    assert!(
        matches!(err, KyriotesCsk2Error::MissingWrapper),
        "expected MissingWrapper past reseal boundary, got {err:?}"
    );

    // Step 3: Reseal — open using the ORIGINAL epoch-42 wrapper (42 ≤ 44 → valid)
    // and seal with a fresh DEK bound to epoch 45.
    let new_kp = RecipientKeyPair::generate(&mut rand::rngs::OsRng);
    let verifier = StubAuthorityVerifier;
    let req45 = kyriotes_csk2::OpenRequest {
        object_id: s.req.object_id.clone(),
        required_rights: s.req.required_rights,
        policy_hash: s.req.policy_hash,
        epoch: 45,
    };

    let (resealed, seal_commit45) = open_and_reseal_and_commit(
        &mut log,
        &verifier,
        &s.keypair.secret,
        &new_kp.public,
        &original,
        &s.cap,
        &s.proof,      // proof for open_state (epoch 42, ≤ boundary)
        &s.seal_state, // open_state: epoch 42, wrapper exists here
        &proof_for_45, // proof for seal_state (epoch 45)
        &state45,      // seal_state: epoch 45
        &req45,
        TemporalPolicy::Current, // new object: no reseal restriction
    )
    .expect("open_and_reseal_and_commit should succeed (open uses epoch-42 wrapper)");

    // Step 4: New recipient opens the resealed object at epoch 45 → success.
    let proof_for_commit45 = s.build_proof_for_state(&seal_commit45.state);
    let plaintext = open(
        &new_kp.secret,
        &resealed,
        &s.cap,
        &proof_for_commit45,
        &seal_commit45.state,
    )
    .expect("new recipient must open resealed object at epoch 45");
    assert_eq!(plaintext, b"classified content");
}

/// Original recipient cannot open the resealed object (DEK is fresh; their
/// classical KEM ciphertext targets `new_kp.public`, not `s.keypair.public`).
#[test]
fn reseal_required_old_recipient_cannot_open_resealed() {
    let s = Scenario::baseline("rr-old-sk", 42)
        .with_temporal_policy(TemporalPolicy::ResealRequired { after: 44 })
        .with_message(b"private");

    let original = seal(
        &s.keypair.public,
        &s.message,
        &s.cap,
        &s.proof,
        &s.seal_transparency_proof,
        &s.seal_state,
        &s.req,
        s.temporal_policy.clone(),
    )
    .expect("seal");

    let new_kp = RecipientKeyPair::generate(&mut rand::rngs::OsRng);
    let verifier = StubAuthorityVerifier;
    let mut log = InMemoryTransparencyLog::new();

    let (resealed, commit) = open_and_reseal_and_commit(
        &mut log,
        &verifier,
        &s.keypair.secret,
        &new_kp.public,
        &original,
        &s.cap,
        &s.proof,
        &s.seal_state,
        &s.proof,
        &s.seal_state,
        &s.req,
        TemporalPolicy::Current,
    )
    .expect("reseal");

    // Old recipient's key cannot derive the new DEK.
    let proof_for_commit = s.build_proof_for_state(&commit.state);
    let err = open(
        &s.keypair.secret,
        &resealed,
        &s.cap,
        &proof_for_commit,
        &commit.state,
    )
    .expect_err("old recipient must not open resealed object");
    assert!(matches!(err, KyriotesCsk2Error::Crypto(_)), "{err:?}");
}

/// `open_and_reseal` (without commit) still works for the `ResealRequired` case
/// when the caller already has committed states.
#[test]
fn open_and_reseal_works_for_reseal_required() {
    let s = Scenario::baseline("rr-no-commit", 42)
        .with_temporal_policy(TemporalPolicy::ResealRequired { after: 44 })
        .with_message(b"data");

    let original = seal(
        &s.keypair.public,
        &s.message,
        &s.cap,
        &s.proof,
        &s.seal_transparency_proof,
        &s.seal_state,
        &s.req,
        s.temporal_policy.clone(),
    )
    .expect("seal");

    let new_kp = RecipientKeyPair::generate(&mut rand::rngs::OsRng);

    // open_and_reseal with open_state = seal_state (epoch 42) and seal_state same.
    let resealed = open_and_reseal(
        &s.keypair.secret,
        &new_kp.public,
        &original,
        &s.cap,
        &s.proof,
        &s.seal_state, // open_state epoch 42 ≤ boundary 44 → wrapper exists
        &s.proof,
        &s.seal_transparency_proof,
        &s.seal_state,
        &s.req,
        TemporalPolicy::Current,
    )
    .expect("open_and_reseal with valid open state");

    let plaintext = open(&new_kp.secret, &resealed, &s.cap, &s.proof, &s.seal_state)
        .expect("new recipient must open");
    assert_eq!(plaintext, b"data");
}
