use std::time::{Duration, Instant};

fn decode_should_reject_quickly(name: &str, bytes: &[u8], max_duration: Duration) {
    let start = Instant::now();
    let result = arc_core::decode_arc_object(bytes);
    let elapsed = start.elapsed();

    assert!(
        result.is_err(),
        "decode_arc_object unexpectedly accepted invalid parser-refinement vector: {name}"
    );

    assert!(
        elapsed <= max_duration,
        "decode_arc_object took too long for vector {name}: elapsed={elapsed:?}, max={max_duration:?}"
    );
}

fn deterministic_bytes(seed: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut state: u64 = 0xcbf29ce484222325;

    for byte in seed {
        state ^= u64::from(*byte);
        state = state.wrapping_mul(0x100000001b3);
    }

    while out.len() < len {
        state ^= state.rotate_left(13);
        state = state.wrapping_mul(0xff51afd7ed558ccd);
        state ^= state >> 33;
        out.extend_from_slice(&state.to_le_bytes());
    }

    out.truncate(len);
    out
}

#[test]
fn decode_arc_object_rejects_empty_and_tiny_inputs() {
    decode_should_reject_quickly("empty", &[], Duration::from_millis(50));
    decode_should_reject_quickly("single-zero", &[0x00], Duration::from_millis(50));
    decode_should_reject_quickly("single-ff", &[0xff], Duration::from_millis(50));
}

#[test]
fn decode_arc_object_rejects_truncated_inputs() {
    let truncated_32 = deterministic_bytes(b"arc-truncated-32", 32);
    let truncated_127 = deterministic_bytes(b"arc-truncated-127", 127);

    decode_should_reject_quickly("truncated-32", &truncated_32, Duration::from_millis(50));
    decode_should_reject_quickly("truncated-127", &truncated_127, Duration::from_millis(50));
}

#[test]
fn decode_arc_object_rejects_repeated_malformed_inputs() {
    let zeros = vec![0x00; 512];
    let ones = vec![0xff; 512];

    decode_should_reject_quickly("repeated-zero-512", &zeros, Duration::from_millis(100));
    decode_should_reject_quickly("repeated-ff-512", &ones, Duration::from_millis(100));
}

#[test]
fn decode_arc_object_rejects_large_deterministic_garbage() {
    let garbage = deterministic_bytes(b"arc-large-garbage", 4096);

    decode_should_reject_quickly(
        "deterministic-garbage-4096",
        &garbage,
        Duration::from_millis(250),
    );
}

#[test]
fn decode_arc_object_rejection_is_deterministic_for_same_input() {
    let bytes = deterministic_bytes(b"arc-determinism", 256);

    let first = arc_core::decode_arc_object(&bytes).is_err();
    let second = arc_core::decode_arc_object(&bytes).is_err();

    assert!(first);
    assert_eq!(first, second);
}
