/// Integration tests for temporal policy edge cases (spec §10).
///
/// Covers Window and ResealRequired policy boundary semantics, and the
/// cap epoch-range boundary checks (ValidCap spec §9 check 6).
mod helpers;

use helpers::scenario::Scenario;
use helpers::transparency::commit_state;
use kyriotes_csk2::InMemoryTransparencyLog;
use kyriotes_csk2::{KyriotesCsk2Error, TemporalPolicy, add_epoch_wrapper, open, seal};

// ---------------------------------------------------------------------------
// Window temporal policy
// ---------------------------------------------------------------------------

/// Open exactly at window.start (lower boundary) using the seal-epoch wrapper.
///
/// required_wrapper_epoch(Window{42,45}, e_open=42, e_seal=42) = e_open = 42.
/// The object carries a wrapper at epoch 42, so no rewrap is needed.
#[test]
fn window_policy_open_at_window_start() {
    let s = Scenario::baseline("window-start", 42)
        .with_temporal_policy(TemporalPolicy::Window { start: 42, end: 45 });

    let obj = seal(
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

    let plaintext = open(&s.keypair.secret, &obj, &s.cap, &s.proof, &s.seal_state)
        .expect("open at window.start should succeed");
    assert_eq!(plaintext, s.message);
}

/// Open exactly at window.end (upper boundary) after rewrapping for that epoch.
///
/// required_wrapper_epoch(Window{42,45}, e_open=45, e_seal=42) = e_open = 45.
/// A wrapper at epoch 45 must exist; add_epoch_wrapper provides it.
#[test]
fn window_policy_open_at_window_end_after_rewrap() {
    let s = Scenario::baseline("window-end", 42)
        .with_temporal_policy(TemporalPolicy::Window { start: 42, end: 45 });

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
    .expect("seal should succeed");

    let mut log = InMemoryTransparencyLog::new();
    let seed45 = s.make_state_at_epoch(45);
    let (state45, tp45) = commit_state(&mut log, &seed45).expect("commit epoch 45");
    let proof45 = s.build_proof_for_state(&state45);

    add_epoch_wrapper(
        &s.keypair.secret,
        &s.keypair.public,
        &mut obj,
        &s.cap,
        &s.proof,
        &s.seal_state,
        &state45,
        &tp45,
    )
    .expect("rewrap to epoch 45 should succeed");

    let plaintext = open(&s.keypair.secret, &obj, &s.cap, &proof45, &state45)
        .expect("open at window.end should succeed");
    assert_eq!(plaintext, s.message);
}

/// Opening with e_open < window.start is rejected with TemporalRejected.
///
/// Window(42,45).accepts(41, 42) = false → TemporalRejected before any proof check.
#[test]
fn window_policy_rejects_below_window_start() {
    let s = Scenario::baseline("window-below-start", 42)
        .with_temporal_policy(TemporalPolicy::Window { start: 42, end: 45 });

    let obj = seal(
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

    let mut log = InMemoryTransparencyLog::new();
    let seed41 = s.make_state_at_epoch(41);
    let (state41, _) = commit_state(&mut log, &seed41).expect("commit epoch 41");

    // TemporalAccept is evaluated first; proof validity is irrelevant here.
    let err = open(&s.keypair.secret, &obj, &s.cap, &s.proof, &state41)
        .expect_err("epoch 41 is below window.start=42 and must be rejected");
    assert!(
        matches!(err, KyriotesCsk2Error::TemporalRejected),
        "{err:?}"
    );
}

/// Opening with e_open > window.end is rejected with TemporalRejected.
///
/// Window(42,45).accepts(46, 42) = false.
#[test]
fn window_policy_rejects_above_window_end() {
    let s = Scenario::baseline("window-above-end", 42)
        .with_temporal_policy(TemporalPolicy::Window { start: 42, end: 45 });

    let obj = seal(
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

    let mut log = InMemoryTransparencyLog::new();
    let seed46 = s.make_state_at_epoch(46);
    let (state46, _) = commit_state(&mut log, &seed46).expect("commit epoch 46");

    let err = open(&s.keypair.secret, &obj, &s.cap, &s.proof, &state46)
        .expect_err("epoch 46 is above window.end=45 and must be rejected");
    assert!(
        matches!(err, KyriotesCsk2Error::TemporalRejected),
        "{err:?}"
    );
}

// ---------------------------------------------------------------------------
// ResealRequired temporal policy
// ---------------------------------------------------------------------------

/// Opening before the reseal boundary succeeds using the seal-epoch wrapper.
///
/// required_wrapper_epoch(ResealRequired{44}, e_open=42, e_seal=42) = e_seal = 42.
/// The original wrapper at epoch 42 is used.
#[test]
fn reseal_required_open_before_boundary_uses_seal_wrapper() {
    let s = Scenario::baseline("reseal-before", 42)
        .with_temporal_policy(TemporalPolicy::ResealRequired { after: 44 });

    let obj = seal(
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

    // Pass the seal-epoch state; e_open = 42 ≤ after=44 → use seal-epoch wrapper.
    let plaintext = open(&s.keypair.secret, &obj, &s.cap, &s.proof, &s.seal_state)
        .expect("open before reseal boundary should succeed with seal-epoch wrapper");
    assert_eq!(plaintext, s.message);
}

/// Opening past the reseal boundary without a new wrapper returns MissingWrapper,
/// signalling the caller to reseal before retrying.
///
/// required_wrapper_epoch(ResealRequired{44}, e_open=45, e_seal=42) = e_open = 45.
/// No wrapper exists at epoch 45 → MissingWrapper.
#[test]
fn reseal_required_open_past_boundary_returns_missing_wrapper() {
    let s = Scenario::baseline("reseal-past", 42)
        .with_temporal_policy(TemporalPolicy::ResealRequired { after: 44 });

    let obj = seal(
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

    let mut log = InMemoryTransparencyLog::new();
    let seed45 = s.make_state_at_epoch(45);
    let (state45, _) = commit_state(&mut log, &seed45).expect("commit epoch 45");

    // e_open=45 > after=44 → required_wrapper_epoch = 45.  No wrapper at 45.
    let err = open(&s.keypair.secret, &obj, &s.cap, &s.proof, &state45)
        .expect_err("past reseal boundary without rewrap must fail");
    assert!(matches!(err, KyriotesCsk2Error::MissingWrapper), "{err:?}");
}

// ---------------------------------------------------------------------------
// Capability epoch range boundaries (ValidCap §9 check 6)
// ---------------------------------------------------------------------------

/// Seal and open exactly at cap.epoch_start (lower boundary of capability validity).
///
/// sample_cap uses epoch_start=40.  All cap validity checks must pass at epoch 40.
#[test]
fn seal_open_at_cap_epoch_start() {
    let s = Scenario::baseline("cap-epoch-start", 40);

    let obj = seal(
        &s.keypair.public,
        &s.message,
        &s.cap,
        &s.proof,
        &s.seal_transparency_proof,
        &s.seal_state,
        &s.req,
        s.temporal_policy.clone(),
    )
    .expect("seal at cap.epoch_start should succeed");

    let plaintext = open(&s.keypair.secret, &obj, &s.cap, &s.proof, &s.open_state)
        .expect("open at cap.epoch_start should succeed");
    assert_eq!(plaintext, s.message);
}

/// Seal and open exactly at cap.epoch_end (upper boundary of capability validity).
///
/// sample_cap uses epoch_end=60.
#[test]
fn seal_open_at_cap_epoch_end() {
    let s = Scenario::baseline("cap-epoch-end", 60);

    let obj = seal(
        &s.keypair.public,
        &s.message,
        &s.cap,
        &s.proof,
        &s.seal_transparency_proof,
        &s.seal_state,
        &s.req,
        s.temporal_policy.clone(),
    )
    .expect("seal at cap.epoch_end should succeed");

    let plaintext = open(&s.keypair.secret, &obj, &s.cap, &s.proof, &s.open_state)
        .expect("open at cap.epoch_end should succeed");
    assert_eq!(plaintext, s.message);
}

/// Seal is rejected when the epoch cert was issued before cap.epoch_start.
///
/// epoch_cert.epoch=39 < cap.epoch_start=40 → verify_capability_issuance step 3
/// returns an error ("epoch cert epoch is outside capability validity range"),
/// remapped to InvalidCapability("invalid issuance signature") in validate_capability.
#[test]
fn seal_rejects_epoch_cert_before_cap_start() {
    let s = Scenario::baseline("cap-epoch-before-start", 39);

    let err = seal(
        &s.keypair.public,
        &s.message,
        &s.cap,
        &s.proof,
        &s.seal_transparency_proof,
        &s.seal_state,
        &s.req,
        s.temporal_policy.clone(),
    )
    .expect_err("epoch before cap.epoch_start must be rejected");

    assert!(
        matches!(err, KyriotesCsk2Error::InvalidCapability(_)),
        "{err:?}"
    );
}

/// Seal is rejected when the epoch cert was issued after cap.epoch_end.
///
/// epoch_cert.epoch=61 > cap.epoch_end=60 → same step 3 check.
#[test]
fn seal_rejects_epoch_cert_after_cap_end() {
    let s = Scenario::baseline("cap-epoch-after-end", 61);

    let err = seal(
        &s.keypair.public,
        &s.message,
        &s.cap,
        &s.proof,
        &s.seal_transparency_proof,
        &s.seal_state,
        &s.req,
        s.temporal_policy.clone(),
    )
    .expect_err("epoch after cap.epoch_end must be rejected");

    assert!(
        matches!(err, KyriotesCsk2Error::InvalidCapability(_)),
        "{err:?}"
    );
}
