mod helpers;

use arc_core::{ArcError, TemporalPolicy, add_epoch_wrapper, open, seal};
use helpers::scenario::Scenario;

#[test]
fn seal_open_historical_success() {
    let s = Scenario::baseline("only-valid-current-capability", 42)
        .with_message(b"secret bytes");

    let object = seal(
        &s.keypair.public,
        &s.message,
        &s.cap,
        &s.proof,
        &s.seal_transparency_proof,
        &s.seal_state,
        &s.req,
        s.temporal_policy.clone(),
    )
    .expect("seal should succeed");

    let opened = open(&s.keypair.secret, &object, &s.cap, &s.proof, &s.open_state)
        .expect("open should succeed");
    assert_eq!(opened, b"secret bytes");
}

#[test]
fn current_policy_requires_rewrap_for_new_epoch() {
    let s42 = Scenario::baseline("current-only", 42)
        .with_temporal_policy(TemporalPolicy::Current)
        .with_message(b"draft-v1");

    let s50 = Scenario::baseline("current-only", 42).with_open_epoch(50);

    let mut object = seal(
        &s42.keypair.public,
        &s42.message,
        &s42.cap,
        &s42.proof,
        &s42.seal_transparency_proof,
        &s42.seal_state,
        &s42.req,
        s42.temporal_policy.clone(),
    )
    .expect("seal should succeed");

    let err = open(
        &s42.keypair.secret,
        &object,
        &s42.cap,
        &s42.proof,
        &s50.open_state,
    )
    .expect_err("wrapper for epoch 50 missing");
    assert!(matches!(err, ArcError::MissingWrapper));

    add_epoch_wrapper(
        &s42.keypair.secret,
        &s42.keypair.public,
        &mut object,
        &s42.cap,
        &s42.proof,
        &s42.seal_state,
        &s50.open_state,
        &s50.open_transparency_proof,
    )
        .expect("rewrap should succeed");

    let opened = open(
        &s42.keypair.secret,
        &object,
        &s42.cap,
        &s42.proof,
        &s50.open_state,
    )
    .expect("open after rewrap succeeds");
    assert_eq!(opened, b"draft-v1");
}

#[test]
fn open_with_wrong_recipient_key_fails() {
    use arc_core::RecipientKeyPair;

    let s = Scenario::baseline("wrong-key", 42).with_message(b"secret");

    let object = seal(
        &s.keypair.public,
        &s.message,
        &s.cap,
        &s.proof,
        &s.seal_transparency_proof,
        &s.seal_state,
        &s.req,
        s.temporal_policy.clone(),
    )
    .expect("seal should succeed");

    // Different keypair — X25519 DH produces a different shared secret,
    // so AEAD authentication on the wrapped DEK will fail.
    let wrong_keypair = RecipientKeyPair::generate(&mut rand::rngs::OsRng);
    let err = open(&wrong_keypair.secret, &object, &s.cap, &s.proof, &s.open_state)
        .expect_err("wrong recipient key must cause decryption failure");

    assert!(matches!(err, ArcError::Crypto(_)));
}
