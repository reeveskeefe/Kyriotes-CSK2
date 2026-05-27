/// Wire encode/decode round-trip tests for `Capability` and `ThresholdSignatureSet`.
///
/// Verifies:
/// - All `Capability` fields survive a round-trip, including `delegation_depth`
///   and `parent_stamp` for both directly-issued and delegated capabilities.
/// - `ThresholdSignatureSet` survives a round-trip, including empty sets
///   and multi-signer sets.
/// - Decoders reject truncated input, trailing bytes, and oversized counts.
use arc_core::{
    ArcError,
    Capability,
    Rights,
    ThresholdPartialSig, ThresholdSignatureSet,
    decode_capability,
    decode_capability_with_limits,
    encode_capability,
    decode_threshold_signature_set,
    decode_threshold_signature_set_with_max,
    encode_threshold_signature_set,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn direct_cap() -> Capability {
    Capability {
        version: 1,
        subject: "subject-alice".to_string(),
        object_id: "object-doc-42".to_string(),
        rights: Rights::READ.union(Rights::DECRYPT),
        policy_hash: [0xAB; 32],
        epoch_start: 1,
        epoch_end: 10,
        delegation_depth: 0,
        parent_stamp: [0u8; 32],
        nonce: [0x12; 16],
    }
}

fn delegated_cap() -> Capability {
    Capability {
        version: 1,
        subject: "subject-bob".to_string(),
        object_id: "object-doc-42".to_string(),
        rights: Rights::READ,
        policy_hash: [0xCD; 32],
        epoch_start: 3,
        epoch_end: 8,
        delegation_depth: 1,
        parent_stamp: [0x77; 32],
        nonce: [0x34; 16],
    }
}

// ---------------------------------------------------------------------------
// Capability round-trip tests
// ---------------------------------------------------------------------------

/// A directly-issued capability (delegation_depth=0, parent_stamp all-zero) round-trips.
#[test]
fn capability_roundtrip_direct_issue() {
    let cap = direct_cap();
    let encoded = encode_capability(&cap);
    let decoded = decode_capability(&encoded).expect("decode must succeed");
    assert_eq!(decoded, cap);
}

/// A delegated capability (delegation_depth=1, non-zero parent_stamp) round-trips.
#[test]
fn capability_roundtrip_delegated() {
    let cap = delegated_cap();
    let encoded = encode_capability(&cap);
    let decoded = decode_capability(&encoded).expect("decode must succeed");
    assert_eq!(decoded, cap);
    assert_eq!(decoded.delegation_depth, 1);
    assert_eq!(decoded.parent_stamp, [0x77; 32]);
}

/// delegation_depth values > 1 also survive (no clamping in the wire layer).
#[test]
fn capability_roundtrip_deep_delegation_depth() {
    let mut cap = direct_cap();
    cap.delegation_depth = 255;
    cap.parent_stamp = [0xFF; 32];
    let encoded = encode_capability(&cap);
    let decoded = decode_capability(&encoded).expect("decode must succeed");
    assert_eq!(decoded.delegation_depth, 255);
    assert_eq!(decoded.parent_stamp, [0xFF; 32]);
}

/// Decoded capability fields match exactly what was encoded, field by field.
#[test]
fn capability_all_fields_survive_roundtrip() {
    let cap = Capability {
        version: 1,
        subject: "sub-test".to_string(),
        object_id: "obj-test".to_string(),
        rights: Rights::DELEGATE,
        policy_hash: [0x01; 32],
        epoch_start: 100,
        epoch_end: 200,
        delegation_depth: 2,
        parent_stamp: [0x55; 32],
        nonce: [0xAA; 16],
    };
    let decoded = decode_capability(&encode_capability(&cap)).unwrap();
    assert_eq!(decoded.version, 1);
    assert_eq!(decoded.subject, "sub-test");
    assert_eq!(decoded.object_id, "obj-test");
    assert_eq!(decoded.rights, Rights::DELEGATE);
    assert_eq!(decoded.policy_hash, [0x01; 32]);
    assert_eq!(decoded.epoch_start, 100);
    assert_eq!(decoded.epoch_end, 200);
    assert_eq!(decoded.delegation_depth, 2);
    assert_eq!(decoded.parent_stamp, [0x55; 32]);
    assert_eq!(decoded.nonce, [0xAA; 16]);
}

/// Trailing bytes after a valid capability cause rejection.
#[test]
fn capability_decode_rejects_trailing_bytes() {
    let mut bytes = encode_capability(&direct_cap());
    bytes.push(0x00);
    let err = decode_capability(&bytes).expect_err("trailing byte must fail");
    assert!(matches!(err, ArcError::Parse("trailing bytes after capability")));
}

/// Truncated input causes rejection.
#[test]
fn capability_decode_rejects_truncated_input() {
    let bytes = encode_capability(&direct_cap());
    let truncated = &bytes[..bytes.len() - 4];
    decode_capability(truncated).expect_err("truncated input must fail");
}

/// Subject longer than `max_subject_len` is rejected.
#[test]
fn capability_decode_rejects_oversized_subject() {
    let mut cap = direct_cap();
    cap.subject = "x".repeat(100);
    let bytes = encode_capability(&cap);
    let err = decode_capability_with_limits(&bytes, 10, 1024)
        .expect_err("oversized subject must fail");
    assert!(matches!(err, ArcError::Parse(_)));
}

// ---------------------------------------------------------------------------
// ThresholdSignatureSet round-trip tests
// ---------------------------------------------------------------------------

fn make_partial(index: u32, seed: u8) -> ThresholdPartialSig {
    ThresholdPartialSig { signer_index: index, sig: [seed; 64] }
}

/// A 2-of-3 set with 3 partials round-trips completely.
#[test]
fn tsig_set_roundtrip_2_of_3() {
    let mut set = ThresholdSignatureSet::new(2);
    set.add(make_partial(0, 0xAA));
    set.add(make_partial(1, 0xBB));
    set.add(make_partial(2, 0xCC));

    let encoded = encode_threshold_signature_set(&set);
    let decoded = decode_threshold_signature_set(&encoded).expect("decode must succeed");

    assert_eq!(decoded.threshold, 2);
    assert_eq!(decoded.partials.len(), 3);
    assert_eq!(decoded.partials[0].signer_index, 0);
    assert_eq!(decoded.partials[0].sig, [0xAA; 64]);
    assert_eq!(decoded.partials[2].signer_index, 2);
    assert_eq!(decoded.partials[2].sig, [0xCC; 64]);
}

/// An empty set (threshold=1, no partials) round-trips.
#[test]
fn tsig_set_roundtrip_empty_partials() {
    let set = ThresholdSignatureSet::new(1);
    let encoded = encode_threshold_signature_set(&set);
    let decoded = decode_threshold_signature_set(&encoded).expect("decode must succeed");
    assert_eq!(decoded.threshold, 1);
    assert_eq!(decoded.partials.len(), 0);
}

/// A 1-of-1 set round-trips.
#[test]
fn tsig_set_roundtrip_1_of_1() {
    let mut set = ThresholdSignatureSet::new(1);
    set.add(make_partial(0, 0x11));
    let decoded = decode_threshold_signature_set(&encode_threshold_signature_set(&set)).unwrap();
    assert_eq!(decoded.threshold, 1);
    assert_eq!(decoded.partials[0].sig, [0x11; 64]);
}

/// Trailing bytes after a valid set cause rejection.
#[test]
fn tsig_set_decode_rejects_trailing_bytes() {
    let mut set = ThresholdSignatureSet::new(1);
    set.add(make_partial(0, 0x00));
    let mut bytes = encode_threshold_signature_set(&set);
    bytes.push(0xFF);
    let err = decode_threshold_signature_set(&bytes)
        .expect_err("trailing byte must fail");
    assert!(matches!(err, ArcError::Parse("trailing bytes after threshold signature set")));
}

/// Truncated sig bytes (fewer than 64) cause rejection.
#[test]
fn tsig_set_decode_rejects_truncated_sig() {
    let mut set = ThresholdSignatureSet::new(1);
    set.add(make_partial(0, 0x00));
    let bytes = encode_threshold_signature_set(&set);
    let truncated = &bytes[..bytes.len() - 10]; // cut 10 bytes off the sig
    decode_threshold_signature_set(truncated).expect_err("truncated sig must fail");
}

/// count > max_partials causes rejection.
#[test]
fn tsig_set_decode_rejects_count_exceeding_max() {
    let mut set = ThresholdSignatureSet::new(1);
    for i in 0..5u32 {
        set.add(make_partial(i, i as u8));
    }
    let bytes = encode_threshold_signature_set(&set);
    let err = decode_threshold_signature_set_with_max(&bytes, 3)
        .expect_err("count > max_partials must fail");
    assert!(matches!(
        err,
        ArcError::Parse("partial signature count exceeds maximum allowed")
    ));
}
