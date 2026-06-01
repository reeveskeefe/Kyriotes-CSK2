/// Integration tests for the public `verify` / `verify_with_verifier` functions
/// (spec §2 Verify algorithm).
///
/// `verify` checks the authority certificate chain, temporal policy, and
/// ValidCap predicate without attempting any decryption — a useful pre-flight
/// check and the only verifier path available to relying parties that do not
/// hold `sk_B`.
mod helpers;

use helpers::scenario::Scenario;
use helpers::transparency::commit_state;
use kyriotes_csk2::InMemoryTransparencyLog;
use kyriotes_csk2::{
    Capability, CryptoAuthorityVerifier, KyriotesCsk2Error, Rights, TemporalPolicy, open, seal,
    verify, verify_with_verifier,
};

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
        matches!(err, KyriotesCsk2Error::TemporalRejected)
            || matches!(err, KyriotesCsk2Error::AuthorityState(_)),
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

    let err = verify(
        &object,
        &s.cap,
        &s.proof,
        &bad_state,
        &s.seal_transparency_proof,
    )
    .expect_err("should reject bad epoch sig flag");
    assert!(
        matches!(err, KyriotesCsk2Error::AuthorityState(_)),
        "{err:?}"
    );
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

    let err = verify(
        &object,
        &s.cap,
        &s.proof,
        &bad_state,
        &s.seal_transparency_proof,
    )
    .expect_err("should reject bad cert flag");
    assert!(
        matches!(err, KyriotesCsk2Error::AuthorityState(_)),
        "{err:?}"
    );
}

// ---------------------------------------------------------------------------
// Capability checks
// ---------------------------------------------------------------------------

#[test]
fn verify_rejects_delegated_cap_with_zero_parent_stamp() {
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

    // Construct a cap with delegation_depth = 1 but parent_stamp still zero —
    // must be rejected because spec §5 requires a non-zero parent_stamp for
    // delegation_depth > 0.
    let delegated_cap = Capability {
        delegation_depth: 1,
        ..s.cap.clone() // inherits parent_stamp: [0u8; 32]
    };

    let err = verify(
        &object,
        &delegated_cap,
        &s.proof,
        &s.seal_state,
        &s.seal_transparency_proof,
    )
    .expect_err("delegated cap with zero parent_stamp must be rejected");
    assert!(
        matches!(err, KyriotesCsk2Error::InvalidCapability(_)),
        "{err:?}"
    );
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
    assert!(
        matches!(err, KyriotesCsk2Error::InvalidCapability(_)),
        "{err:?}"
    );
}

#[test]
fn verify_rejects_insufficient_rights() {
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
    assert!(
        matches!(err, KyriotesCsk2Error::InvalidCapability(_)),
        "{err:?}"
    );
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
    let epoch_root_sig = s.authority.epoch_kp.sign_epoch_root(
        &s.seal_state.authority_root,
        &s.seal_state.revocation_root,
        &s.seal_state.transparency_root,
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
    assert!(
        matches!(err, KyriotesCsk2Error::AuthorityState(_)),
        "{err:?}"
    );
}

// ---------------------------------------------------------------------------
// Transparency inclusion flag
// ---------------------------------------------------------------------------

/// Spec §2 step 3: transparency inclusion proof must pass.
/// `AuthorityState::transparency_inclusion_valid = false` signals a failed
/// inclusion check and must cause verify to reject.
#[test]
fn verify_rejects_invalid_transparency_flag() {
    let s = Scenario::baseline("verify-tp-flag", 42).with_message(b"data");

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
    bad_state.transparency_inclusion_valid = false;

    let err = verify(
        &object,
        &s.cap,
        &s.proof,
        &bad_state,
        &s.seal_transparency_proof,
    )
    .expect_err("should reject when transparency inclusion flag is false");
    assert!(
        matches!(err, KyriotesCsk2Error::AuthorityState(_)),
        "{err:?}"
    );
}

// ---------------------------------------------------------------------------
// Capability epoch window expiry
// ---------------------------------------------------------------------------

/// Spec §2 step 5 → ValidCap §9 check 6: e_req must fall within
/// [cap.epoch_start, cap.epoch_end].  If the capability's validity window
/// has ended before the open epoch, verify must reject.
#[test]
fn verify_rejects_cap_epoch_window_expired() {
    // Seal at epoch 42.  Cap covers epochs [40, 60] (from sample_cap).
    // Open at epoch 65 — past cap.epoch_end=60 — with a wider temporal
    // window [40, 70] so TemporalAccept passes but ValidCap check 6 rejects.
    //
    // Note: before the V7 fix (epoch-independent capability_stamp), this test
    // accidentally passed because a mismatched stamp caused a false "revoked"
    // error when verifying at a different epoch.  Now we deliberately push the
    // open epoch beyond cap.epoch_end to exercise the real epoch-window guard.
    let s = Scenario::baseline("verify-epoch-expired", 42).with_message(b"payload");

    let object = seal(
        &s.keypair.public,
        &s.message,
        &s.cap,
        &s.proof,
        &s.seal_transparency_proof,
        &s.seal_state,
        &s.req,
        TemporalPolicy::Window { start: 40, end: 70 }, // wider than cap so TemporalAccept passes
    )
    .expect("seal");

    // Build an authority state at epoch 65 — past cap.epoch_end (60).
    let mut late_seed = s.seal_state.clone();
    late_seed.epoch = 65;
    let mut log = InMemoryTransparencyLog::new();
    let (late_state, late_proof) = commit_state(&mut log, &late_seed).expect("commit");

    let err = verify(&object, &s.cap, &s.proof, &late_state, &late_proof)
        .expect_err("cap epoch window expired — should reject");
    assert!(
        matches!(err, KyriotesCsk2Error::InvalidCapability(_))
            || matches!(err, KyriotesCsk2Error::AuthorityState(_)),
        "unexpected error variant: {err:?}",
    );
}

// ---------------------------------------------------------------------------
// Verify / Open consistency
// ---------------------------------------------------------------------------

/// If verify passes, open with the same arguments must also succeed and return
/// the correct plaintext.  This confirms the two entry points are consistent.
#[test]
fn verify_and_open_agree_on_valid_object() {
    let s = Scenario::baseline("verify-open-agree", 42).with_message(b"consistency check");

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

    // verify must pass first.
    verify(
        &object,
        &s.cap,
        &s.proof,
        &s.open_state,
        &s.open_transparency_proof,
    )
    .expect("verify should succeed");

    // open with the same state must also succeed and produce the same plaintext.
    let plaintext = open(&s.keypair.secret, &object, &s.cap, &s.proof, &s.open_state)
        .expect("open should succeed when verify passes");

    assert_eq!(plaintext, s.message);
}
