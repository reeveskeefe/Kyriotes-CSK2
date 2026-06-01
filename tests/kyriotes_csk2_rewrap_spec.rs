/// Spec §15 Rewrap precondition tests for `add_epoch_wrapper`.
///
/// Verifies:
/// - Spec §15 precondition A_to.epoch > A_from.epoch is enforced (backward and equal rewrap rejected).
/// - to_state.epoch must be within [cap.epoch_start, cap.epoch_end].
/// - Happy-path rewrap to a strictly later epoch within the cap window succeeds.
mod helpers;

use helpers::scenario::Scenario;
use helpers::transparency::commit_state;
use kyriotes_csk2::InMemoryTransparencyLog;
use kyriotes_csk2::{KyriotesCsk2Error, TemporalPolicy, add_epoch_wrapper, open, seal};

// ---------------------------------------------------------------------------
// Helper: seal an object at the scenario's baseline epoch.
// ---------------------------------------------------------------------------
fn sealed_object(s: &Scenario) -> kyriotes_csk2::KyriotesCsk2Object {
    seal(
        &s.keypair.public,
        &s.message,
        &s.cap,
        &s.proof,
        &s.seal_transparency_proof,
        &s.seal_state,
        &s.req,
        s.temporal_policy.clone(),
    )
    .expect("seal should succeed")
}

// ---------------------------------------------------------------------------
// Spec §15 precondition: A_to.epoch > A_from.epoch
// ---------------------------------------------------------------------------

/// Rewrapping to a strictly earlier epoch (backward) must be rejected.
#[test]
fn rewrap_rejects_backward_epoch() {
    // Baseline at epoch 50, cap valid 40..60.
    let s = Scenario::baseline("rewrap-backward", 50).with_temporal_policy(TemporalPolicy::Current);
    let mut obj = sealed_object(&s);

    // Try to rewrap FROM epoch 50 TO epoch 45 (backward).
    let mut log = InMemoryTransparencyLog::new();
    let seed45 = s.make_state_at_epoch(45);
    let (state45, tp45) = commit_state(&mut log, &seed45).expect("commit epoch 45");

    let err = add_epoch_wrapper(
        &s.keypair.secret,
        &s.keypair.public,
        &mut obj,
        &s.cap,
        &s.proof,
        &s.seal_state, // from: epoch 50
        &state45,      // to: epoch 45 — backward
        &tp45,
    )
    .expect_err("backward rewrap must be rejected");

    assert!(
        matches!(
            err,
            KyriotesCsk2Error::InvalidCapability(
                "rewrap target epoch must be strictly later than source epoch"
            )
        ),
        "unexpected error: {err:?}"
    );
}

/// Rewrapping to the same epoch as the source must be rejected.
#[test]
fn rewrap_rejects_same_epoch() {
    let s = Scenario::baseline("rewrap-same", 50).with_temporal_policy(TemporalPolicy::Current);
    let mut obj = sealed_object(&s);

    // Use the same state for both from and to.
    let err = add_epoch_wrapper(
        &s.keypair.secret,
        &s.keypair.public,
        &mut obj,
        &s.cap,
        &s.proof,
        &s.seal_state, // from: epoch 50
        &s.seal_state, // to: same epoch 50
        &s.seal_transparency_proof,
    )
    .expect_err("same-epoch rewrap must be rejected");

    assert!(
        matches!(
            err,
            KyriotesCsk2Error::InvalidCapability(
                "rewrap target epoch must be strictly later than source epoch"
            )
        ),
        "unexpected error: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// to_state epoch must lie within [cap.epoch_start, cap.epoch_end]
// ---------------------------------------------------------------------------

/// Rewrapping to an epoch strictly after cap.epoch_end must be rejected.
#[test]
fn rewrap_rejects_to_epoch_after_cap_end() {
    // Baseline at epoch 42, cap valid 40..60.
    let s =
        Scenario::baseline("rewrap-to-after-end", 42).with_temporal_policy(TemporalPolicy::Current);
    let mut obj = sealed_object(&s);

    let mut log = InMemoryTransparencyLog::new();
    let seed_over = s.make_state_at_epoch(61); // cap.epoch_end = 60
    let (state_over, tp_over) = commit_state(&mut log, &seed_over).expect("commit epoch 61");

    let err = add_epoch_wrapper(
        &s.keypair.secret,
        &s.keypair.public,
        &mut obj,
        &s.cap,
        &s.proof,
        &s.seal_state,
        &state_over,
        &tp_over,
    )
    .expect_err("to-epoch after cap_end must be rejected");

    assert!(
        matches!(
            err,
            KyriotesCsk2Error::InvalidCapability("epoch outside capability validity")
        ),
        "unexpected error: {err:?}"
    );
}

/// Rewrapping to an epoch strictly before cap.epoch_start must be rejected.
///
/// (Previously allowed by the old check which only tested `from_state.epoch < cap.epoch_start`.)
#[test]
fn rewrap_rejects_to_epoch_before_cap_start() {
    // Scenario at epoch 50 (within cap range 40..60).
    let s = Scenario::baseline("rewrap-to-before-start", 50)
        .with_temporal_policy(TemporalPolicy::Current);
    let mut obj = sealed_object(&s);

    // Manufacture a second state at epoch 55 so we can use epoch 50 as "from".
    // Then try rewrapping TO epoch 30, which is before cap.epoch_start = 40.
    //
    // First add a real wrapper at epoch 55, then try an impossible rewrap from 55 to 30.
    // We can't have to < from, so instead we simulate it differently:
    // seal at epoch 30 (which IS before cap_start=40) to get a "from" wrapper,
    // then try to rewrap to epoch 31 (also before cap_start).
    //
    // Simpler: seal at epoch 50, try rewrap to epoch 51 (ok) then from 51 to epoch 30 (before start).
    // Actually, the simplest path: we need the from wrapper to exist.
    // Use seal_state (epoch 50) as from, try to rewrap to an epoch that is
    // strictly AFTER 50 but also BEFORE cap.epoch_start (40).
    // That's impossible (>50 and <40 can't both be true).
    //
    // The only way to test this is with a cap whose epoch_start > 1, from a wrapper
    // that exists at an epoch < cap_start.  Build such a scenario manually.
    //
    // cap valid 40..60, seal at epoch 42.
    // Manually craft a second state at epoch 45. Try rewrap from 42 to 35 (< 40 = cap_start).
    // That requires to=35 < from=42, which is already caught by the backward-epoch check.
    //
    // To isolate the cap_start check from the backward check, we need:
    //   from < to, but to < cap_start.
    // This requires from < to < cap_start.
    // With cap_start=40: from=30, to=35.
    // But from=30 < cap_start=40, and validate_capability will reject from_state.epoch < cap_start.
    //
    // Conclusion: when to_state.epoch < cap.epoch_start, we also have to <= from (since from >= cap_start
    // via ValidCap), so the new `to > from` check fires first.  The `to < cap_start` branch
    // is reachable only through a non-standard code path that bypasses validate_capability.
    // This test documents the expected error for completeness — it's caught by the backward check.
    let mut log = InMemoryTransparencyLog::new();
    let seed30 = s.make_state_at_epoch(30); // before cap.epoch_start = 40
    let (state30, tp30) = commit_state(&mut log, &seed30).expect("commit epoch 30");

    let err = add_epoch_wrapper(
        &s.keypair.secret,
        &s.keypair.public,
        &mut obj,
        &s.cap,
        &s.proof,
        &s.seal_state, // from: epoch 50
        &state30,      // to: epoch 30 — before cap_start AND backward
        &tp30,
    )
    .expect_err("to-epoch before cap_start must be rejected");

    // Caught by backward-epoch check first (30 <= 50).
    assert!(
        matches!(
            err,
            KyriotesCsk2Error::InvalidCapability(
                "rewrap target epoch must be strictly later than source epoch"
            )
        ),
        "unexpected error: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Happy-path sanity check
// ---------------------------------------------------------------------------

/// Rewrap to a strictly later epoch within the cap window succeeds and
/// the new wrapper can be used to open the object.
#[test]
fn rewrap_happy_path_produces_openable_wrapper() {
    let s = Scenario::baseline("rewrap-happy", 42)
        .with_temporal_policy(TemporalPolicy::Current)
        .with_message(b"rewrap test msg");
    let mut obj = sealed_object(&s);

    let mut log = InMemoryTransparencyLog::new();
    let seed55 = s.make_state_at_epoch(55);
    let (state55, tp55) = commit_state(&mut log, &seed55).expect("commit epoch 55");

    add_epoch_wrapper(
        &s.keypair.secret,
        &s.keypair.public,
        &mut obj,
        &s.cap,
        &s.proof,
        &s.seal_state,
        &state55,
        &tp55,
    )
    .expect("valid forward rewrap must succeed");

    assert_eq!(obj.wrappers.len(), 2);

    let proof55 = s.build_proof_for_state(&state55);
    let plaintext = open(&s.keypair.secret, &obj, &s.cap, &proof55, &state55)
        .expect("open with new wrapper must succeed");
    assert_eq!(plaintext, b"rewrap test msg");
}
