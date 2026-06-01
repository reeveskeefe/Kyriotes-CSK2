#![cfg(kani)]
#![allow(dead_code)]

use crate::kyriotes_csk2::model::AuthorityState;
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

fn authority_state(seed: u8, epoch: u64) -> AuthorityState {
    AuthorityState {
        authority_root: bytes32(seed),
        revocation_root: bytes32(seed.wrapping_add(1)),
        transparency_root: bytes32(seed.wrapping_add(2)),
        epoch,
        authority_id: "kani-authority".to_string(),
        epoch_signature_valid: true,
        epoch_key_cert_valid: true,
        transparency_inclusion_valid: true,
        root_pk: bytes32(seed.wrapping_add(3)),
        revocation_count: 0,
        prev_epoch_hash: bytes32(seed.wrapping_add(4)),
    }
}

fn fold_bytes(mut acc: u64, bytes: &[u8]) -> u64 {
    let mut i = 0usize;

    while i < bytes.len() {
        acc = acc.wrapping_mul(16777619);
        acc ^= bytes[i] as u64;
        i += 1;
    }

    acc
}

fn fold_bytes32(acc: u64, bytes: [u8; 32]) -> u64 {
    fold_bytes(acc, &bytes)
}

fn fold_temporal_policy(acc: u64, policy: &TemporalPolicy) -> u64 {
    match policy {
        TemporalPolicy::Historical(epoch) => acc.wrapping_mul(131).wrapping_add(*epoch),
        TemporalPolicy::Current => acc.wrapping_mul(131).wrapping_add(1),
        TemporalPolicy::Window { start, end } => acc
            .wrapping_mul(131)
            .wrapping_add(*start)
            .wrapping_mul(131)
            .wrapping_add(*end),
        TemporalPolicy::ResealRequired { after } => acc.wrapping_mul(131).wrapping_add(*after),
    }
}

fn context_transcript_model(
    object_id: &str,
    required_rights: Rights,
    policy_hash: [u8; 32],
    state: &AuthorityState,
    cap_stamp: [u8; 32],
    temporal_policy: &TemporalPolicy,
) -> u64 {
    let mut acc = 0xcbf29ce484222325u64;

    acc = fold_bytes(acc, b"KYRIOTES-CSK2-CONTEXT-v1");
    acc = fold_bytes(acc, object_id.as_bytes());
    acc = acc.wrapping_mul(131).wrapping_add(required_rights.0 as u64);
    acc = fold_bytes32(acc, policy_hash);
    acc = acc.wrapping_mul(131).wrapping_add(state.epoch);
    acc = fold_bytes32(acc, state.authority_root);
    acc = fold_bytes32(acc, state.revocation_root);
    acc = fold_bytes32(acc, state.transparency_root);
    acc = fold_bytes32(acc, cap_stamp);
    acc = fold_bytes(acc, state.authority_id.as_bytes());
    acc = fold_temporal_policy(acc, temporal_policy);

    acc
}

#[kani::proof]
fn context_transcript_model_is_deterministic_for_equal_inputs() {
    let object_id = "kani-context-object";
    let rights = Rights::READ;
    let policy_hash = bytes32(11);
    let state = authority_state(29, 7);
    let cap_stamp = bytes32(41);
    let temporal_policy = TemporalPolicy::Current;

    let first = context_transcript_model(
        object_id,
        rights,
        policy_hash,
        &state,
        cap_stamp,
        &temporal_policy,
    );

    let second = context_transcript_model(
        object_id,
        rights,
        policy_hash,
        &state,
        cap_stamp,
        &temporal_policy,
    );

    assert_eq!(first, second);
}

#[kani::proof]
fn context_transcript_model_binds_policy_hash() {
    let object_id = "kani-context-object";
    let rights = Rights::READ;
    let state = authority_state(29, 7);
    let cap_stamp = bytes32(41);
    let temporal_policy = TemporalPolicy::Current;

    let first = context_transcript_model(
        object_id,
        rights,
        bytes32(11),
        &state,
        cap_stamp,
        &temporal_policy,
    );

    let second = context_transcript_model(
        object_id,
        rights,
        bytes32(12),
        &state,
        cap_stamp,
        &temporal_policy,
    );

    assert_ne!(first, second);
}

#[kani::proof]
fn context_transcript_model_binds_epoch() {
    let object_id = "kani-context-object";
    let rights = Rights::READ;
    let policy_hash = bytes32(11);
    let first_state = authority_state(29, 7);
    let second_state = authority_state(29, 8);
    let cap_stamp = bytes32(41);
    let temporal_policy = TemporalPolicy::Current;

    let first = context_transcript_model(
        object_id,
        rights,
        policy_hash,
        &first_state,
        cap_stamp,
        &temporal_policy,
    );

    let second = context_transcript_model(
        object_id,
        rights,
        policy_hash,
        &second_state,
        cap_stamp,
        &temporal_policy,
    );

    assert_ne!(first, second);
}

#[kani::proof]
fn context_transcript_model_binds_capability_stamp() {
    let object_id = "kani-context-object";
    let rights = Rights::READ;
    let policy_hash = bytes32(11);
    let state = authority_state(29, 7);
    let temporal_policy = TemporalPolicy::Current;

    let first = context_transcript_model(
        object_id,
        rights,
        policy_hash,
        &state,
        bytes32(41),
        &temporal_policy,
    );

    let second = context_transcript_model(
        object_id,
        rights,
        policy_hash,
        &state,
        bytes32(42),
        &temporal_policy,
    );

    assert_ne!(first, second);
}
