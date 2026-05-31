#![allow(dead_code)]

use arc_core::arc::model::context_hash;

fn bytes32(seed: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut i = 0usize;

    while i < 32 {
        out[i] = seed.wrapping_add(i as u8);
        i += 1;
    }

    out
}

#[cfg(kani)]
#[kani::proof]
fn context_hash_is_deterministic_for_equal_inputs() {
    let object_id = "kani-context-object";
    let rights = arc_core::Rights::READ;
    let policy_hash = bytes32(11);
    let authority_root = bytes32(29);
    let epoch = 7u64;
    let temporal_policy = arc_core::TemporalPolicy::Unbounded;

    let first = context_hash(
        object_id,
        rights,
        policy_hash,
        authority_root,
        epoch,
        &temporal_policy,
    );

    let second = context_hash(
        object_id,
        rights,
        policy_hash,
        authority_root,
        epoch,
        &temporal_policy,
    );

    assert_eq!(first, second);
    assert_eq!(first.len(), 32);
}

#[cfg(kani)]
#[kani::proof]
fn context_hash_distinguishes_policy_hash_inputs() {
    let object_id = "kani-context-object";
    let rights = arc_core::Rights::READ;
    let authority_root = bytes32(29);
    let epoch = 7u64;
    let temporal_policy = arc_core::TemporalPolicy::Unbounded;

    let first = context_hash(
        object_id,
        rights,
        bytes32(11),
        authority_root,
        epoch,
        &temporal_policy,
    );

    let second = context_hash(
        object_id,
        rights,
        bytes32(12),
        authority_root,
        epoch,
        &temporal_policy,
    );

    assert_ne!(first, second);
}
