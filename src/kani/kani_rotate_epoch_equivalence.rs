#![cfg(kani)]
#![allow(dead_code)]

use crate::kyriotes_csk2::engine::rotated_authority_state;
use crate::kyriotes_csk2::model::AuthorityState;

fn bytes32(seed: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut i = 0usize;

    while i < 32 {
        out[i] = seed.wrapping_add(i as u8);
        i += 1;
    }

    out
}

fn base_authority_state() -> AuthorityState {
    AuthorityState {
        authority_root: bytes32(11),
        revocation_root: bytes32(12),
        transparency_root: bytes32(13),
        epoch: 7,
        authority_id: "kani-authority".to_string(),
        root_pk: bytes32(14),
        revocation_count: 42,
        prev_epoch_hash: bytes32(15),
    }
}

#[kani::proof]
fn rotate_epoch_state_sets_requested_epoch() {
    let base = base_authority_state();
    let prev = bytes32(21);
    let rotated = rotated_authority_state(&base, 8, &prev);

    assert_eq!(rotated.epoch, 8);
}

#[kani::proof]
fn rotate_epoch_state_preserves_authority_roots_and_root_key() {
    let base = base_authority_state();
    let prev = bytes32(21);
    let rotated = rotated_authority_state(&base, 8, &prev);

    assert_eq!(rotated.authority_root, base.authority_root);
    assert_eq!(rotated.revocation_root, base.revocation_root);
    assert_eq!(rotated.root_pk, base.root_pk);
}

#[kani::proof]
fn rotate_epoch_state_preserves_authority_identity_and_revocation_count() {
    let base = base_authority_state();
    let prev = bytes32(21);
    let rotated = rotated_authority_state(&base, 8, &prev);

    assert_eq!(rotated.authority_id, base.authority_id);
    assert_eq!(rotated.revocation_count, base.revocation_count);
}

#[kani::proof]
fn rotate_epoch_state_resets_transparency_root() {
    let base = base_authority_state();
    let prev = bytes32(21);
    let rotated = rotated_authority_state(&base, 8, &prev);

    assert_eq!(rotated.transparency_root, [0u8; 32]);
}

#[kani::proof]
fn rotate_epoch_state_binds_previous_epoch_hash() {
    let base = base_authority_state();
    let prev = bytes32(21);
    let rotated = rotated_authority_state(&base, 8, &prev);

    assert_eq!(rotated.prev_epoch_hash, prev);
}

#[kani::proof]
fn rotate_epoch_state_is_deterministic_for_equal_inputs() {
    let base = base_authority_state();
    let prev = bytes32(21);

    let first = rotated_authority_state(&base, 8, &prev);
    let second = rotated_authority_state(&base, 8, &prev);

    assert_eq!(first, second);
}
