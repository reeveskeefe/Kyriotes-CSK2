/// Integration tests for the Threshold Signature (TSIG) scheme (spec §2 TSIG).
///
/// Verifies:
/// - `tsig_sign` produces valid partial signatures
/// - `tsig_verify` accepts a set meeting the threshold
/// - `tsig_verify` rejects a set below the threshold
/// - Duplicate signer indices are counted only once
/// - Out-of-range signer indices are skipped gracefully
/// - Threshold = 0 is rejected
/// - Threshold > n is rejected
/// - A tampered partial signature is not counted
/// - 1-of-n and n-of-n edge cases work correctly
use kyriotes_csk2::{
    EpochSigningKeyPair, ThresholdPartialSig, ThresholdSignatureSet, tsig_epoch_signing_message,
    tsig_sign, tsig_verify,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Generate `n` fresh epoch signing key pairs and return (key_pairs, verifying_keys).
fn make_n_signers(n: usize) -> (Vec<EpochSigningKeyPair>, Vec<[u8; 32]>) {
    let mut rng = rand::rngs::OsRng;
    let kps: Vec<EpochSigningKeyPair> = (0..n)
        .map(|_| EpochSigningKeyPair::generate(&mut rng))
        .collect();
    let vks: Vec<[u8; 32]> = kps.iter().map(|kp| kp.verifying_key_bytes()).collect();
    (kps, vks)
}

const ROOT: [u8; 32] = [1u8; 32];
const REV: [u8; 32] = [2u8; 32];
const TRANSPARENCY_ROOT: [u8; 32] = [3u8; 32];
const EPOCH: u64 = 42;
const PREV: [u8; 32] = [0u8; 32];

// ---------------------------------------------------------------------------
// Basic sign / verify
// ---------------------------------------------------------------------------

/// A single-signer 1-of-1 threshold passes when the signature is correct.
#[test]
fn tsig_1_of_1_passes() {
    let (kps, vks) = make_n_signers(1);
    let mut set = ThresholdSignatureSet::new(1);
    set.add(tsig_sign(
        &ROOT,
        &REV,
        &TRANSPARENCY_ROOT,
        EPOCH,
        &PREV,
        &kps[0],
        0,
    ));
    tsig_verify(&ROOT, &REV, &TRANSPARENCY_ROOT, EPOCH, &PREV, &set, &vks)
        .expect("1-of-1 should pass");
}

/// A 2-of-3 threshold passes when exactly 2 of the 3 participants sign.
#[test]
fn tsig_2_of_3_passes_with_two_sigs() {
    let (kps, vks) = make_n_signers(3);
    let mut set = ThresholdSignatureSet::new(2);
    set.add(tsig_sign(
        &ROOT,
        &REV,
        &TRANSPARENCY_ROOT,
        EPOCH,
        &PREV,
        &kps[0],
        0,
    ));
    set.add(tsig_sign(
        &ROOT,
        &REV,
        &TRANSPARENCY_ROOT,
        EPOCH,
        &PREV,
        &kps[2],
        2,
    ));
    tsig_verify(&ROOT, &REV, &TRANSPARENCY_ROOT, EPOCH, &PREV, &set, &vks)
        .expect("2-of-3 with 2 valid sigs should pass");
}

/// A 3-of-3 threshold passes when all three participants sign.
#[test]
fn tsig_3_of_3_passes_with_all_sigs() {
    let (kps, vks) = make_n_signers(3);
    let mut set = ThresholdSignatureSet::new(3);
    for (i, kp) in kps.iter().enumerate() {
        set.add(tsig_sign(
            &ROOT,
            &REV,
            &TRANSPARENCY_ROOT,
            EPOCH,
            &PREV,
            kp,
            i as u32,
        ));
    }
    tsig_verify(&ROOT, &REV, &TRANSPARENCY_ROOT, EPOCH, &PREV, &set, &vks)
        .expect("3-of-3 with all sigs should pass");
}

// ---------------------------------------------------------------------------
// Threshold not met
// ---------------------------------------------------------------------------

/// A 2-of-3 threshold fails when only 1 participant signs.
#[test]
fn tsig_2_of_3_fails_with_one_sig() {
    let (kps, vks) = make_n_signers(3);
    let mut set = ThresholdSignatureSet::new(2);
    set.add(tsig_sign(
        &ROOT,
        &REV,
        &TRANSPARENCY_ROOT,
        EPOCH,
        &PREV,
        &kps[1],
        1,
    ));
    let err = tsig_verify(&ROOT, &REV, &TRANSPARENCY_ROOT, EPOCH, &PREV, &set, &vks)
        .expect_err("2-of-3 with 1 sig should fail");
    assert!(
        matches!(err, kyriotes_csk2::KyriotesCsk2Error::Crypto(_)),
        "{err:?}"
    );
}

/// An empty signature set never meets any non-zero threshold.
#[test]
fn tsig_empty_set_fails() {
    let (_, vks) = make_n_signers(2);
    let set = ThresholdSignatureSet::new(1);
    tsig_verify(&ROOT, &REV, &TRANSPARENCY_ROOT, EPOCH, &PREV, &set, &vks)
        .expect_err("empty set must not meet threshold 1");
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

/// Threshold = 0 is always rejected as invalid input.
#[test]
fn tsig_threshold_zero_is_rejected() {
    let (kps, vks) = make_n_signers(1);
    let mut set = ThresholdSignatureSet::new(0);
    set.add(tsig_sign(
        &ROOT,
        &REV,
        &TRANSPARENCY_ROOT,
        EPOCH,
        &PREV,
        &kps[0],
        0,
    ));
    let err = tsig_verify(&ROOT, &REV, &TRANSPARENCY_ROOT, EPOCH, &PREV, &set, &vks)
        .expect_err("threshold 0 must be rejected");
    assert!(
        matches!(err, kyriotes_csk2::KyriotesCsk2Error::Crypto(_)),
        "{err:?}"
    );
}

/// Threshold > number of authorized keys is rejected.
#[test]
fn tsig_threshold_exceeds_key_count_is_rejected() {
    let (kps, vks) = make_n_signers(2);
    let mut set = ThresholdSignatureSet::new(3); // 3 > len(vks)=2
    for (i, kp) in kps.iter().enumerate() {
        set.add(tsig_sign(
            &ROOT,
            &REV,
            &TRANSPARENCY_ROOT,
            EPOCH,
            &PREV,
            kp,
            i as u32,
        ));
    }
    let err = tsig_verify(&ROOT, &REV, &TRANSPARENCY_ROOT, EPOCH, &PREV, &set, &vks)
        .expect_err("threshold > n must be rejected");
    assert!(
        matches!(err, kyriotes_csk2::KyriotesCsk2Error::Crypto(_)),
        "{err:?}"
    );
}

/// Duplicate signer_index values are counted only once, even if both
/// partial signatures are valid.
#[test]
fn tsig_duplicate_signer_index_counted_once() {
    let (kps, vks) = make_n_signers(2);
    let mut set = ThresholdSignatureSet::new(2);
    // Add signer 0 twice — should count as only 1 valid signer.
    set.add(tsig_sign(
        &ROOT,
        &REV,
        &TRANSPARENCY_ROOT,
        EPOCH,
        &PREV,
        &kps[0],
        0,
    ));
    set.add(tsig_sign(
        &ROOT,
        &REV,
        &TRANSPARENCY_ROOT,
        EPOCH,
        &PREV,
        &kps[0],
        0,
    )); // duplicate
    let err = tsig_verify(&ROOT, &REV, &TRANSPARENCY_ROOT, EPOCH, &PREV, &set, &vks)
        .expect_err("duplicate index must count only once, failing threshold 2-of-2");
    assert!(
        matches!(err, kyriotes_csk2::KyriotesCsk2Error::Crypto(_)),
        "{err:?}"
    );
}

/// An out-of-range signer_index is silently skipped; it does not contribute
/// to the threshold count.
#[test]
fn tsig_out_of_range_index_is_skipped() {
    let (kps, vks) = make_n_signers(2);
    let mut set = ThresholdSignatureSet::new(2);
    set.add(tsig_sign(
        &ROOT,
        &REV,
        &TRANSPARENCY_ROOT,
        EPOCH,
        &PREV,
        &kps[0],
        0,
    ));
    // Index 99 is out of range for a 2-key set.
    set.add(ThresholdPartialSig {
        signer_index: 99,
        sig: tsig_sign(&ROOT, &REV, &TRANSPARENCY_ROOT, EPOCH, &PREV, &kps[1], 1).sig,
    });
    let err = tsig_verify(&ROOT, &REV, &TRANSPARENCY_ROOT, EPOCH, &PREV, &set, &vks)
        .expect_err("out-of-range index must be skipped, failing threshold 2-of-2");
    assert!(
        matches!(err, kyriotes_csk2::KyriotesCsk2Error::Crypto(_)),
        "{err:?}"
    );
}

/// A tampered signature byte renders the partial signature invalid and it
/// is not counted toward the threshold.
#[test]
fn tsig_tampered_sig_not_counted() {
    let (kps, vks) = make_n_signers(3);
    let mut partial = tsig_sign(&ROOT, &REV, &TRANSPARENCY_ROOT, EPOCH, &PREV, &kps[1], 1);
    partial.sig[0] ^= 0xFF; // tamper first byte

    let mut set = ThresholdSignatureSet::new(2);
    set.add(tsig_sign(
        &ROOT,
        &REV,
        &TRANSPARENCY_ROOT,
        EPOCH,
        &PREV,
        &kps[0],
        0,
    ));
    set.add(partial); // tampered — should not count
    let err = tsig_verify(&ROOT, &REV, &TRANSPARENCY_ROOT, EPOCH, &PREV, &set, &vks)
        .expect_err("tampered sig must not count toward threshold");
    assert!(
        matches!(err, kyriotes_csk2::KyriotesCsk2Error::Crypto(_)),
        "{err:?}"
    );
}

// ---------------------------------------------------------------------------
// Signing message sensitivity
// ---------------------------------------------------------------------------

/// Partial signatures produced for one epoch state do not verify against
/// a different epoch state.
#[test]
fn tsig_sigs_bound_to_epoch_state() {
    let (kps, vks) = make_n_signers(2);
    const OTHER_ROOT: [u8; 32] = [9u8; 32];

    let mut set = ThresholdSignatureSet::new(2);
    // Sign the OTHER_ROOT message.
    set.add(tsig_sign(
        &OTHER_ROOT,
        &REV,
        &TRANSPARENCY_ROOT,
        EPOCH,
        &PREV,
        &kps[0],
        0,
    ));
    set.add(tsig_sign(
        &OTHER_ROOT,
        &REV,
        &TRANSPARENCY_ROOT,
        EPOCH,
        &PREV,
        &kps[1],
        1,
    ));

    // Verify against the original ROOT — must fail.
    let err = tsig_verify(&ROOT, &REV, &TRANSPARENCY_ROOT, EPOCH, &PREV, &set, &vks)
        .expect_err("sigs for OTHER_ROOT must not verify against ROOT");
    assert!(
        matches!(err, kyriotes_csk2::KyriotesCsk2Error::Crypto(_)),
        "{err:?}"
    );
}

/// `tsig_epoch_signing_message` is sensitive to every field.
#[test]
fn tsig_signing_message_is_sensitive_to_all_fields() {
    let base = tsig_epoch_signing_message(&ROOT, &REV, &TRANSPARENCY_ROOT, EPOCH, &PREV);

    let diff_root = tsig_epoch_signing_message(&[9u8; 32], &REV, &TRANSPARENCY_ROOT, EPOCH, &PREV);
    let diff_rev = tsig_epoch_signing_message(&ROOT, &[9u8; 32], &TRANSPARENCY_ROOT, EPOCH, &PREV);
    let diff_transparency = tsig_epoch_signing_message(&ROOT, &REV, &[9u8; 32], EPOCH, &PREV);
    let diff_epoch = tsig_epoch_signing_message(&ROOT, &REV, &TRANSPARENCY_ROOT, EPOCH + 1, &PREV);
    let diff_prev = tsig_epoch_signing_message(&ROOT, &REV, &TRANSPARENCY_ROOT, EPOCH, &[9u8; 32]);

    assert_ne!(base, diff_root, "authority_root must affect message");
    assert_ne!(base, diff_rev, "revocation_root must affect message");
    assert_ne!(
        base, diff_transparency,
        "transparency_root must affect message"
    );
    assert_ne!(base, diff_epoch, "epoch must affect message");
    assert_ne!(base, diff_prev, "prev_epoch_hash must affect message");
}

// ---------------------------------------------------------------------------
// Large committee
// ---------------------------------------------------------------------------

/// A 5-of-7 committee: any 5 of the 7 participants can reach quorum.
#[test]
fn tsig_5_of_7_quorum() {
    let (kps, vks) = make_n_signers(7);

    // Sign with participants 0, 2, 3, 5, 6 — 5 out of 7.
    let signers = [0usize, 2, 3, 5, 6];
    let mut set = ThresholdSignatureSet::new(5);
    for &i in &signers {
        set.add(tsig_sign(
            &ROOT,
            &REV,
            &TRANSPARENCY_ROOT,
            EPOCH,
            &PREV,
            &kps[i],
            i as u32,
        ));
    }
    tsig_verify(&ROOT, &REV, &TRANSPARENCY_ROOT, EPOCH, &PREV, &set, &vks)
        .expect("5-of-7 with 5 valid sigs should pass");

    // Only 4 of the 7 — should fail.
    let mut short_set = ThresholdSignatureSet::new(5);
    for &i in &signers[..4] {
        short_set.add(tsig_sign(
            &ROOT,
            &REV,
            &TRANSPARENCY_ROOT,
            EPOCH,
            &PREV,
            &kps[i],
            i as u32,
        ));
    }
    tsig_verify(
        &ROOT,
        &REV,
        &TRANSPARENCY_ROOT,
        EPOCH,
        &PREV,
        &short_set,
        &vks,
    )
    .expect_err("4-of-7 must not meet threshold 5");
}
