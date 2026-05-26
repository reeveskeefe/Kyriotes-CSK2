/// Integration tests for the public `verify` / `verify_with_verifier` functions
/// (spec §2 Verify algorithm).
///
/// `verify` checks the authority certificate chain, temporal policy, and
/// ValidCap predicate without attempting any decryption — a useful pre-flight
/// check and the only verifier path available to relying parties that do not
/// hold `sk_B`.
mod helpers;

use arc_core::{
    ArcError, Capability, Rights, TemporalPolicy,
    open, seal, verify, verify_with_verifier,
    BasicAuthorityVerifier, CryptoAuthorityVerifier, AuthorityEpochEvidence,
    hash_policy,
};
use helpers::scenario::Scenario;
use helpers::transparency::commit_state;
use arc_core::InMemoryTransparencyLog;

// ---------------------------------------------------------------------------
// Happy-path
// ---------------------------------------------------------------------------

#[test]
fn verify_succeeds_for_valid_sealed_object() {
    let s = Scenario::baseline("verify-happy", 42).with_message(b"hello");

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
    .expect("seal");

    verify(
        &object,
        &s.cap,
        &s.proof,
        &s.seal_state,
        &s.seal_transparency_proof,
    )
    .expect("verify should succeed");
}

#[test]
fn verify_does_not_require_secret_key() {
    // This test confirms verify() compiles and runs without any sk_B.
    let s = Scenario::baseline("verify-no-sk", 42).with_message(b"private");

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
    .expect("seal");

    // Deliberately do NOT call open; only verify.
    verify(
        &object,
        &s.cap,
        &s.proof,
        &s.seal_state,
        &s.seal_transparency_proof,
    )
    .expect("verify should succeed without sk_B");
}

// ---------------------------------------------------------------------------
// Temporal policy
// ---------------------------------------------------------------------------

#[test]
fn verify_rejects_temporal_policy_epoch_mismatch() {
    // Seal at epoch 20 with Historical(20), then try to verify with a state at
    // epoch 30 — TemporalAccept returns false because 30 ≠ 20.
    let s = Scenario::baseline("verify-temporal", 42).with_message(b"data");

    let object = seal(
        &s.keypair.public,
        &s.message,
        &s.cap,
        &s.proof,
        &s.seal_transparency_proof,
        &s.seal_state,
        &s.req,
        TemporalPolicy::Historical(42),
    )
    .expect("seal");

    let wrong_state = s.make_state_at_epoch(55);
    let mut log = InMemoryTransparencyLog::new();
    let (wrong_state, wrong_proof) = commit_state(&mut log, &wrong_state).expect("commit");

    let err = verify(&object, &s.cap, &s.proof, &wrong_state, &wrong_proof)
        .expect_err("should reject wrong epoch");
    assert!(
        matches!(err, ArcError::TemporalRejected)
            || matches!(err, ArcError::AuthorityState(_)),
        "unexpected error: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Authority-state flag checks
// ---------------------------------------------------------------------------

#[test]
fn verify_rejects_invalid_epoch_signature_flag() {
    let s = Scenario::baseline("verify-sig-flag", 42).with_message(b"x");

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
    .expect("seal");

    let mut bad_state = s.seal_state.clone();
    bad_state.epoch_signature_valid = false;

    let err = verify(&object, &s.cap, &s.proof, &bad_state, &s.seal_transparency_proof)
        .expect_err("should reject bad epoch sig flag");
    assert!(matches!(err, ArcError::AuthorityState(_)), "{err:?}");
}

#[test]
fn verify_rejects_invalid_epoch_cert_flag() {
    let s = Scenario::baseline("verify-cert-flag", 42).with_message(b"y");

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
    .expect("seal");

    let mut bad_state = s.seal_state.clone();
    bad_state.epoch_key_cert_valid = false;

    let err = verify(&object, &s.cap, &s.proof, &bad_state, &s.seal_transparency_proof)
        .expect_err("should reject bad cert flag");
    assert!(matches!(err, ArcError::AuthorityState(_)), "{err:?}");
}

// ---------------------------------------------------------------------------
// Capability checks
// ---------------------------------------------------------------------------

#[test]
fn verify_rejects_delegation_depth_nonzero() {
    let s = Scenario::baseline("verify-delegation", 42).with_message(b"delegated");

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
    .expect("seal");

    // Construct a cap with delegation_depth = 1 (same leaf data except delegation_depth).
    let delegated_cap = Capability {
        delegation_depth: 1,
        ..s.cap.clone()
    };

    let err = verify(
        &object,
        &delegated_cap,
        &s.proof,
        &s.seal_state,
        &s.seal_transparency_proof,
    )
    .expect_err("should reject delegation_depth > 0");
    assert!(matches!(err, ArcError::InvalidCapability(_)), "{err:?}");
}

#[test]
fn verify_rejects_wrong_object_id() {
    let s = Scenario::baseline("verify-obj-id", 42).with_message(b"payload");

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
    .expect("seal");

    let wrong_cap = Capability {
        object_id: "different-object.dat".to_string(),
        ..s.cap.clone()
    };

    let err = verify(
        &object,
        &wrong_cap,
        &s.proof,
        &s.seal_state,
        &s.seal_transparency_proof,
    )
    .expect_err("should reject cap with wrong object_id");
    assert!(matches!(err, ArcError::InvalidCapability(_)), "{err:?}");
}

#[test]
fn verify_rejects_insufficient_rights() {
    use arc_core::OpenRequest;
    let s = Scenario::baseline("verify-rights", 42).with_message(b"payload");

    // Seal with required_rights = READ | DECRYPT (from Scenario defaults).
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
    .expect("seal");

    // A cap that only grants READ cannot satisfy the object's required DECRYPT right.
    let read_only_cap = Capability {
        rights: Rights::READ,
        ..s.cap.clone()
    };

    let err = verify(
        &object,
        &read_only_cap,
        &s.proof,
        &s.seal_state,
        &s.seal_transparency_proof,
    )
    .expect_err("should reject cap with insufficient rights");
    assert!(matches!(err, ArcError::InvalidCapability(_)), "{err:?}");
}

// ---------------------------------------------------------------------------
// CryptoAuthorityVerifier path
// ---------------------------------------------------------------------------

#[test]
fn verify_with_crypto_verifier_succeeds() {
    let s = Scenario::baseline("verify-crypto-verifier", 42).with_message(b"real crypto");

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
    .expect("seal");

    // Build a CryptoAuthorityVerifier with the offline root public key and
    // enough evidence to pass epoch chain verification.
    let epoch_root_sig = s
        .authority
        .epoch_kp
        .sign_epoch_root(
            &s.seal_state.authority_root,
            &s.seal_state.revocation_root,
            s.seal_state.epoch,
            &[0u8; 32],
        );

    let mut verifier = CryptoAuthorityVerifier::with_root_pk(s.authority.root_pk());
    verifier.add_evidence(
        &s.seal_state.authority_id,
        s.seal_state.epoch,
        s.authority.epoch_kp.verifying_key_bytes(),
        epoch_root_sig,
        s.authority.epoch_cert.clone(),
    );

    verify_with_verifier(
        &verifier,
        &object,
        &s.cap,
        &s.proof,
        &s.seal_state,
        &s.seal_transparency_proof,
    )
    .expect("CryptoAuthorityVerifier verify should succeed");
}

#[test]
fn verify_with_crypto_verifier_rejects_missing_evidence() {
    let s = Scenario::baseline("verify-crypto-no-evidence", 42).with_message(b"data");

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
    .expect("seal");

    // Verifier has correct root_pk but no evidence registered.
    let verifier = CryptoAuthorityVerifier::with_root_pk(s.authority.root_pk());

    let err = verify_with_verifier(
        &verifier,
        &object,
        &s.cap,
        &s.proof,
        &s.seal_state,
        &s.seal_transparency_proof,
    )
    .expect_err("should fail without evidence");
    assert!(matches!(err, ArcError::AuthorityState(_)), "{err:?}");
}
