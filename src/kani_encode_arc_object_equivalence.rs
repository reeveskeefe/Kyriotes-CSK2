#![cfg(kani)]
#![allow(dead_code)]

use crate::{ArcObject, Rights, TemporalPolicy, encode_arc_object};

fn bytes32(seed: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut i = 0usize;

    while i < 32 {
        out[i] = seed.wrapping_add(i as u8);
        i += 1;
    }

    out
}

fn bytes12(seed: u8) -> [u8; 12] {
    let mut out = [0u8; 12];
    let mut i = 0usize;

    while i < 12 {
        out[i] = seed.wrapping_add(i as u8);
        i += 1;
    }

    out
}

fn minimal_arc_object_with_object_id(object_id: &str) -> ArcObject {
    ArcObject {
        version: 1,
        suite: "ARC-KANI-SUITE".to_string(),
        object_id: object_id.to_string(),
        required_rights: Rights::READ,
        policy_hash: bytes32(11),
        seal_epoch: 7,
        temporal_policy: TemporalPolicy::Current,
        authority_root: bytes32(29),
        revocation_root: bytes32(41),
        payload_nonce: bytes12(53),
        payload_ciphertext: vec![1u8, 2u8, 3u8, 4u8],
        wrappers: Vec::new(),
    }
}

fn minimal_arc_object() -> ArcObject {
    minimal_arc_object_with_object_id("kani-object")
}

#[kani::proof]
fn encode_arc_object_is_deterministic_for_equal_input() {
    let object = minimal_arc_object();

    let first = encode_arc_object(&object);
    let second = encode_arc_object(&object);

    assert_eq!(first, second);
}

#[kani::proof]
fn encode_arc_object_returns_non_empty_bytes() {
    let object = minimal_arc_object();
    let encoded = encode_arc_object(&object);

    assert!(!encoded.is_empty());
}

#[kani::proof]
fn encode_arc_object_starts_with_arc_magic() {
    let object = minimal_arc_object();
    let encoded = encode_arc_object(&object);

    assert!(encoded.len() >= 4);
    assert_eq!(encoded[0], b'A');
    assert_eq!(encoded[1], b'R');
    assert_eq!(encoded[2], b'C');
    assert_eq!(encoded[3], 1u8);
}

#[kani::proof]
fn encode_arc_object_version_one_layout_is_stable() {
    let object = minimal_arc_object();
    let encoded = encode_arc_object(&object);

    assert!(encoded.len() >= 6);
    assert_eq!(encoded[4], 0u8);
    assert_eq!(encoded[5], 1u8);
}

#[kani::proof]
fn encode_arc_object_binds_object_id() {
    let first = minimal_arc_object_with_object_id("kani-object-a");
    let second = minimal_arc_object_with_object_id("kani-object-b");

    let first_encoded = encode_arc_object(&first);
    let second_encoded = encode_arc_object(&second);

    assert_ne!(first_encoded, second_encoded);
}
