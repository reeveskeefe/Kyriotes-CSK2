#![allow(dead_code)]

use crate::kyriotes_csk2::model::AuthorityState;
use crate::kyriotes_csk2::model::context_hash;
use crate::{Rights, TemporalPolicy};

fn bytes32(seed: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut i = 0usize;

    while i < 32 {
        out[i] = seed.wrapping_add(i as u8);
        i += 1;
    }

    out
}

fn authority_state(authority_root: [u8; 32], epoch: u64) -> AuthorityState {
    AuthorityState {
        authority_root,
        revocation_root: bytes32(31),
        transparency_root: bytes32(37),
        epoch,
        authority_id: "kani-authority".to_string(),
        root_pk: bytes32(41),
        revocation_count: 0,
        prev_epoch_hash: bytes32(43),
    }
}

#[cfg(kani)]
#[kani::proof]
fn context_hash_is_deterministic_for_equal_inputs() {
    let object_id = "kani-context-object";
    let rights = Rights::READ;
    let policy_hash = bytes32(11);
    let authority_root = bytes32(29);
    let state = authority_state(authority_root, 7);
    let cap_stamp = bytes32(47);
    let temporal_policy = TemporalPolicy::Current;

    let first = context_hash(
        object_id,
        rights,
        policy_hash,
        &state,
        cap_stamp,
        &temporal_policy,
    );

    let second = context_hash(
        object_id,
        rights,
        policy_hash,
        &state,
        cap_stamp,
        &temporal_policy,
    );

    assert_eq!(first, second);
    assert_eq!(first.len(), 32);
}

#[cfg(kani)]
#[kani::proof]
fn context_hash_distinguishes_policy_hash_inputs() {
    let object_id = "kani-context-object";
    let rights = Rights::READ;
    let authority_root = bytes32(29);
    let state = authority_state(authority_root, 7);
    let cap_stamp = bytes32(47);
    let temporal_policy = TemporalPolicy::Current;

    let first = context_hash(
        object_id,
        rights,
        bytes32(11),
        &state,
        cap_stamp,
        &temporal_policy,
    );

    let second = context_hash(
        object_id,
        rights,
        bytes32(12),
        &state,
        cap_stamp,
        &temporal_policy,
    );

    assert_ne!(first, second);
}
