#![cfg(kani)]
#![allow(dead_code)]

use crate::kyriotes_csk2::model::AuthorityState;
use crate::kyriotes_csk2::transparency::bind_transparency_root_to_state;

fn bytes32(seed: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut i = 0usize;

    while i < 32 {
        out[i] = seed.wrapping_add(i as u8);
        i += 1;
    }

    out
}

fn authority_state() -> AuthorityState {
    AuthorityState {
        authority_root: bytes32(11),
        revocation_root: bytes32(12),
        transparency_root: [0u8; 32],
        epoch: 7,
        authority_id: "kani-authority".to_string(),
        epoch_signature_valid: true,
        epoch_key_cert_valid: true,
        transparency_inclusion_valid: true,
        root_pk: bytes32(13),
        revocation_count: 42,
        prev_epoch_hash: bytes32(14),
    }
}

#[kani::proof]
fn transparency_bind_root_preserves_authority_root() {
    let state = authority_state();
    let root = bytes32(91);

    let committed = bind_transparency_root_to_state(&state, root);

    assert_eq!(committed.authority_root, state.authority_root);
}

#[kani::proof]
fn transparency_bind_root_preserves_revocation_root() {
    let state = authority_state();
    let root = bytes32(91);

    let committed = bind_transparency_root_to_state(&state, root);

    assert_eq!(committed.revocation_root, state.revocation_root);
}

#[kani::proof]
fn transparency_bind_root_preserves_epoch_and_authority_identity() {
    let state = authority_state();
    let root = bytes32(91);

    let committed = bind_transparency_root_to_state(&state, root);

    assert_eq!(committed.epoch, state.epoch);
    assert_eq!(committed.authority_id, state.authority_id);
}

#[kani::proof]
fn transparency_bind_root_preserves_revocation_count_and_prev_hash() {
    let state = authority_state();
    let root = bytes32(91);

    let committed = bind_transparency_root_to_state(&state, root);

    assert_eq!(committed.revocation_count, state.revocation_count);
    assert_eq!(committed.prev_epoch_hash, state.prev_epoch_hash);
}

#[kani::proof]
fn transparency_bind_root_sets_supplied_transparency_root() {
    let state = authority_state();
    let root = bytes32(91);

    let committed = bind_transparency_root_to_state(&state, root);

    assert_eq!(committed.transparency_root, root);
}

#[kani::proof]
fn transparency_bind_root_is_deterministic_for_equal_inputs() {
    let state = authority_state();
    let root = bytes32(91);

    let first = bind_transparency_root_to_state(&state, root);
    let second = bind_transparency_root_to_state(&state, root);

    assert_eq!(first, second);
}
