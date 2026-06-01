#![cfg(kani)]
#![allow(dead_code)]

use crate::kyriotes_csk2::capability_tree::{NonRevocationWitness, verify_non_revocation};

fn bytes32(seed: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut i = 0usize;

    while i < 32 {
        out[i] = seed.wrapping_add(i as u8);
        i += 1;
    }

    out
}

fn empty_non_revocation_witness() -> NonRevocationWitness {
    NonRevocationWitness {
        stamp: bytes32(11),
        total_revoked: 0,
        left: None,
        right: None,
    }
}

#[kani::proof]
fn capability_tree_non_revocation_accepts_empty_set_witness() {
    let witness = empty_non_revocation_witness();
    let revocation_root = [0u8; 32];

    let result = verify_non_revocation(&witness, &revocation_root, 0);

    assert!(result.is_ok());
}

#[kani::proof]
fn capability_tree_non_revocation_rejects_empty_set_with_nonzero_root() {
    let witness = empty_non_revocation_witness();
    let revocation_root = bytes32(91);

    let result = verify_non_revocation(&witness, &revocation_root, 0);

    assert!(result.is_err());
}

#[kani::proof]
fn capability_tree_non_revocation_rejects_mismatched_authenticated_count() {
    let witness = empty_non_revocation_witness();
    let revocation_root = [0u8; 32];

    let result = verify_non_revocation(&witness, &revocation_root, 1);

    assert!(result.is_err());
}

#[kani::proof]
fn capability_tree_non_revocation_empty_rejection_is_deterministic() {
    let witness = empty_non_revocation_witness();
    let revocation_root = bytes32(91);

    let first = verify_non_revocation(&witness, &revocation_root, 0).is_err();
    let second = verify_non_revocation(&witness, &revocation_root, 0).is_err();

    assert_eq!(first, second);
    assert!(first);
}

#[kani::proof]
fn capability_tree_non_revocation_empty_acceptance_is_deterministic() {
    let witness = empty_non_revocation_witness();
    let revocation_root = [0u8; 32];

    let first = verify_non_revocation(&witness, &revocation_root, 0).is_ok();
    let second = verify_non_revocation(&witness, &revocation_root, 0).is_ok();

    assert_eq!(first, second);
    assert!(first);
}
