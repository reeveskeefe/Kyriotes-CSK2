#![cfg(kani)]
#![allow(dead_code)]

use crate::kyriotes_csk2::capability_tree::{
    capability_proof_leaf_matches, merkle_sibling_is_right_child, next_merkle_index,
    non_revocation_boundaries_are_adjacent, non_revocation_left_is_last,
    non_revocation_left_order_valid, non_revocation_right_is_first,
    non_revocation_right_order_valid,
};

#[kani::proof]
fn capability_tree_production_leaf_binding_is_exact() {
    let proof_leaf: [u8; 32] = kani::any();
    let expected_leaf: [u8; 32] = kani::any();

    assert_eq!(
        capability_proof_leaf_matches(&proof_leaf, &expected_leaf),
        proof_leaf == expected_leaf
    );
}

#[kani::proof]
fn capability_tree_production_merkle_direction_uses_index_parity() {
    let index: u64 = kani::any();

    assert_eq!(merkle_sibling_is_right_child(index), index % 2 == 0);
}

#[kani::proof]
fn capability_tree_production_merkle_index_advances_to_parent() {
    let index: u64 = kani::any();

    assert_eq!(next_merkle_index(index), index / 2);
}

#[kani::proof]
fn capability_tree_production_left_order_is_strict() {
    let left: [u8; 32] = kani::any();
    let target: [u8; 32] = kani::any();

    assert_eq!(
        non_revocation_left_order_valid(&left, &target),
        left < target
    );
}

#[kani::proof]
fn capability_tree_production_right_order_is_strict() {
    let target: [u8; 32] = kani::any();
    let right: [u8; 32] = kani::any();

    assert_eq!(
        non_revocation_right_order_valid(&target, &right),
        target < right
    );
}

#[kani::proof]
fn capability_tree_production_left_only_requires_last_leaf() {
    let left_index: u64 = kani::any();
    let count: u64 = kani::any();

    if non_revocation_left_is_last(left_index, count) {
        assert!(count > 0);
        assert_eq!(left_index, count - 1);
    }
}

#[kani::proof]
fn capability_tree_production_right_only_requires_first_leaf() {
    let right_index: u64 = kani::any();

    if non_revocation_right_is_first(right_index) {
        assert_eq!(right_index, 0);
    }
}

#[kani::proof]
fn capability_tree_production_between_bounds_require_adjacency() {
    let left_index: u64 = kani::any();
    let right_index: u64 = kani::any();

    if non_revocation_boundaries_are_adjacent(left_index, right_index) {
        assert!(left_index < u64::MAX);
        assert_eq!(left_index + 1, right_index);
    }
}

#[kani::proof]
fn capability_tree_production_adjacency_rejects_overflow() {
    let right_index: u64 = kani::any();

    assert!(!non_revocation_boundaries_are_adjacent(
        u64::MAX,
        right_index
    ));
}
