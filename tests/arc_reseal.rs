/// Integration tests for `open_and_reseal` / `open_and_reseal_with_verifier`
/// (spec §15 Reseal algorithm).
///
/// Reseal produces a new ARC object with a fresh DEK and optionally a new
/// recipient public key or new authority state.  The original object is
/// unchanged.
mod helpers;

use arc_core::InMemoryTransparencyLog;
use arc_core::{ArcError, RecipientKeyPair, TemporalPolicy, open, open_and_reseal, seal};
use helpers::scenario::Scenario;
use helpers::transparency::commit_state;

// ---------------------------------------------------------------------------
// Happy-path
// ---------------------------------------------------------------------------

#[test]
fn reseal_produces_openable_object_for_new_recipient() {
    let s = Scenario::baseline("reseal-new-recipient", 45).with_message(b"secret payload");

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

    let resealed = open_and_reseal(
        &s.keypair.secret,
        &new_kp.public,
        &original,
        &s.cap,
        &s.proof,
        &s.seal_state,
        &s.proof,
        &s.seal_transparency_proof,
        &s.seal_state,
        &s.req,
        s.temporal_policy.clone(),
    )
    .expect("open_and_reseal should succeed");

    let recovered = open(&new_kp.secret, &resealed, &s.cap, &s.proof, &s.seal_state)
        .expect("new recipient should be able to open resealed object");
    assert_eq!(recovered, b"secret payload");
}

#[test]
fn reseal_old_recipient_cannot_open_resealed_object() {
    let s = Scenario::baseline("reseal-old-cannot-open", 45).with_message(b"my data");

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

    let resealed = open_and_reseal(
        &s.keypair.secret,
        &new_kp.public,
        &original,
        &s.cap,
        &s.proof,
        &s.seal_state,
        &s.proof,
        &s.seal_transparency_proof,
        &s.seal_state,
        &s.req,
        s.temporal_policy.clone(),
    )
    .expect("open_and_reseal should succeed");

    // The old recipient's KEM ciphertext is for new_kp.public; decapsulation
    // with s.keypair.secret will produce wrong shared secret → AEAD decryption fail.
    let err = open(
        &s.keypair.secret,
        &resealed,
        &s.cap,
        &s.proof,
        &s.seal_state,
    )
    .expect_err("old recipient must not open resealed object");
    assert!(matches!(err, ArcError::Crypto(_)), "{err:?}");
}

#[test]
fn reseal_same_recipient_fresh_ciphertext() {
    // Resealing to the SAME recipient still produces a fresh DEK and therefore
    // a different payload ciphertext.
    let s = Scenario::baseline("reseal-same-recipient", 45).with_message(b"determinism check");

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

    let resealed = open_and_reseal(
        &s.keypair.secret,
        &s.keypair.public,
        &original,
        &s.cap,
        &s.proof,
        &s.seal_state,
        &s.proof,
        &s.seal_transparency_proof,
        &s.seal_state,
        &s.req,
        s.temporal_policy.clone(),
    )
    .expect("open_and_reseal to same recipient");

    assert_ne!(
        original.payload_ciphertext, resealed.payload_ciphertext,
        "fresh DEK should produce different payload ciphertext"
    );

    // Both original and resealed are openable by the same recipient.
    let m1 = open(
        &s.keypair.secret,
        &original,
        &s.cap,
        &s.proof,
        &s.seal_state,
    )
    .expect("original still openable");
    let m2 = open(
        &s.keypair.secret,
        &resealed,
        &s.cap,
        &s.proof,
        &s.seal_state,
    )
    .expect("resealed openable");
    assert_eq!(m1, m2);
}

// ---------------------------------------------------------------------------
// Cross-epoch reseal
// ---------------------------------------------------------------------------

#[test]
fn reseal_cross_epoch_with_new_state() {
    // Seal at epoch 40, reseal for the same cap's epoch range at epoch 45.
    // The capability covers epochs 40–60.
    let s = Scenario::baseline("reseal-cross-epoch", 45).with_message(b"epoch migration");

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
    .expect("seal at epoch 45");

    // Build a new state at epoch 48 (still within cap.epoch_end = 60).
    let mut log = InMemoryTransparencyLog::new();
    let seed48 = s.make_state_at_epoch(48);
    let (state48, proof48) = commit_state(&mut log, &seed48).expect("commit epoch 48");
    let proof48_cap = s.build_proof_for_state(&state48);

    let new_kp = RecipientKeyPair::generate(&mut rand::rngs::OsRng);

    let seal_req48 = arc_core::OpenRequest {
        object_id: s.req.object_id.clone(),
        required_rights: s.req.required_rights,
        policy_hash: s.req.policy_hash,
        epoch: 48,
    };

    let resealed = open_and_reseal(
        &s.keypair.secret,
        &new_kp.public,
        &original,
        &s.cap,
        &s.proof,      // open proof (epoch 45)
        &s.seal_state, // open state (epoch 45)
        &proof48_cap,  // seal proof (epoch 48)
        &proof48,      // seal transparency proof
        &state48,      // seal state (epoch 48)
        &seal_req48,
        TemporalPolicy::Historical(48),
    )
    .expect("cross-epoch reseal should succeed");

    let recovered = open(&new_kp.secret, &resealed, &s.cap, &proof48_cap, &state48)
        .expect("new recipient should open cross-epoch resealed object");
    assert_eq!(recovered, b"epoch migration");
}

// ---------------------------------------------------------------------------
// Error cases
// ---------------------------------------------------------------------------

#[test]
fn reseal_rejects_bad_open_state() {
    let s = Scenario::baseline("reseal-bad-open-state", 45).with_message(b"payload");

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

    // Supply a state at a different epoch — the DEK unwrap will fail because the
    // context hash won't match the wrapper's stored context_hash.
    let wrong_state = s.make_state_at_epoch(99);
    let mut log = InMemoryTransparencyLog::new();
    let (wrong_state, _wrong_proof) = commit_state(&mut log, &wrong_state).expect("commit");
    let wrong_proof = s.build_proof_for_state(&wrong_state);

    let new_kp = RecipientKeyPair::generate(&mut rand::rngs::OsRng);

    let err = open_and_reseal(
        &s.keypair.secret,
        &new_kp.public,
        &original,
        &s.cap,
        &wrong_proof,
        &wrong_state,
        &s.proof,
        &s.seal_transparency_proof,
        &s.seal_state,
        &s.req,
        s.temporal_policy.clone(),
    )
    .expect_err("should fail when open state does not match wrapper epoch");
    assert!(
        matches!(
            err,
            ArcError::MissingWrapper
                | ArcError::AuthorityState(_)
                | ArcError::InvalidCapability(_)
                | ArcError::TemporalRejected
        ),
        "unexpected error variant: {err:?}"
    );
}

#[test]
fn reseal_rejects_wrong_recipient_secret_key() {
    let s = Scenario::baseline("reseal-wrong-sk", 45).with_message(b"payload");

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

    let wrong_kp = RecipientKeyPair::generate(&mut rand::rngs::OsRng);
    let new_kp = RecipientKeyPair::generate(&mut rand::rngs::OsRng);

    // wrong_kp.secret cannot decapsulate a KEM ciphertext encrypted for s.keypair.public.
    let err = open_and_reseal(
        &wrong_kp.secret, // wrong key
        &new_kp.public,
        &original,
        &s.cap,
        &s.proof,
        &s.seal_state,
        &s.proof,
        &s.seal_transparency_proof,
        &s.seal_state,
        &s.req,
        s.temporal_policy.clone(),
    )
    .expect_err("should fail with wrong recipient secret key");
    assert!(matches!(err, ArcError::Crypto(_)), "{err:?}");
}
