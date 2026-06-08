#![cfg(kani)]
#![allow(dead_code)]

use crate::kyriotes_csk2::transparency::{merkle_sibling_is_right, next_merkle_index};

#[kani::proof]
fn transparency_merkle_direction_is_exactly_index_parity() {
    let index: u64 = kani::any();

    assert_eq!(merkle_sibling_is_right(index), index % 2 == 0);
}

#[kani::proof]
fn transparency_merkle_parent_index_is_floor_half() {
    let index: u64 = kani::any();

    assert_eq!(next_merkle_index(index), index / 2);
}

#[kani::proof]
fn transparency_merkle_direction_and_parent_progress_are_deterministic() {
    let index: u64 = kani::any();

    assert_eq!(
        (merkle_sibling_is_right(index), next_merkle_index(index)),
        (merkle_sibling_is_right(index), next_merkle_index(index))
    );
}

#[kani::proof]
fn transparency_merkle_parent_progress_strictly_decreases_positive_indices() {
    let index: u64 = kani::any();
    kani::assume(index > 0);

    assert!(next_merkle_index(index) < index);
}

#[kani::proof]
fn transparency_merkle_even_and_odd_children_share_parent() {
    let parent: u64 = kani::any();
    kani::assume(parent <= (u64::MAX - 1) / 2);

    let left = parent * 2;
    let right = left + 1;

    assert!(merkle_sibling_is_right(left));
    assert!(!merkle_sibling_is_right(right));
    assert_eq!(next_merkle_index(left), parent);
    assert_eq!(next_merkle_index(right), parent);
}
