#![cfg(kani)]
#![allow(dead_code)]

use crate::{
    KyriotesCsk2Object, Rights, TemporalPolicy,
    decode_kyriotes_csk2_object, encode_kyriotes_csk2_object,
};

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

fn minimal_kyriotes_csk2_object_with_object_id(object_id: &str) -> KyriotesCsk2Object {
    KyriotesCsk2Object {
        version: 1,
        suite: "KYRIOTES-CSK2-KANI-SUITE".to_string(),
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

fn minimal_kyriotes_csk2_object() -> KyriotesCsk2Object {
    minimal_kyriotes_csk2_object_with_object_id("kani-object")
}

#[kani::proof]
fn encode_kyriotes_csk2_object_is_deterministic_for_equal_input() {
    let object = minimal_kyriotes_csk2_object();

    let first = encode_kyriotes_csk2_object(&object);
    let second = encode_kyriotes_csk2_object(&object);

    assert_eq!(first, second);
}

#[kani::proof]
fn encode_kyriotes_csk2_object_returns_non_empty_bytes() {
    let object = minimal_kyriotes_csk2_object();
    let encoded = encode_kyriotes_csk2_object(&object);

    assert!(!encoded.is_empty());
}

#[kani::proof]
fn encode_kyriotes_csk2_object_starts_with_kyriotes_csk2_magic() {
    let object = minimal_kyriotes_csk2_object();
    let encoded = encode_kyriotes_csk2_object(&object);

    assert!(encoded.len() >= 4);
    assert_eq!(encoded[0], b'K');
    assert_eq!(encoded[1], b'C');
    assert_eq!(encoded[2], b'S');
    assert_eq!(encoded[3], b'2');
}

#[kani::proof]
fn encode_kyriotes_csk2_object_version_one_layout_is_stable() {
    let object = minimal_kyriotes_csk2_object();
    let encoded = encode_kyriotes_csk2_object(&object);

    assert!(encoded.len() >= 6);
    assert_eq!(encoded[4], 1u8);
    assert_eq!(encoded[5], 0u8);
}

#[kani::proof]
fn encode_kyriotes_csk2_object_binds_object_id() {
    let first = minimal_kyriotes_csk2_object_with_object_id("kani-object-a");
    let second = minimal_kyriotes_csk2_object_with_object_id("kani-object-b");

    let first_encoded = encode_kyriotes_csk2_object(&first);
    let second_encoded = encode_kyriotes_csk2_object(&second);

    assert_ne!(first_encoded, second_encoded);
}

#[kani::proof]
fn encode_decode_roundtrip_preserves_semantic_fields() {
    let object = minimal_kyriotes_csk2_object();
    let encoded = encode_kyriotes_csk2_object(&object);
    let decoded = decode_kyriotes_csk2_object(&encoded);

    assert!(decoded.is_ok());
    let decoded_obj = decoded.unwrap();

    assert_eq!(decoded_obj.version, object.version);
    assert_eq!(decoded_obj.seal_epoch, object.seal_epoch);
    assert_eq!(decoded_obj.policy_hash, object.policy_hash);
    assert_eq!(decoded_obj.authority_root, object.authority_root);
    assert_eq!(decoded_obj.revocation_root, object.revocation_root);
    assert_eq!(decoded_obj.payload_nonce, object.payload_nonce);
    assert_eq!(decoded_obj.required_rights.bits(), object.required_rights.bits());
    assert_eq!(decoded_obj.payload_ciphertext, object.payload_ciphertext);
    assert!(decoded_obj.wrappers.is_empty());
}

#[kani::proof]
fn encode_decode_roundtrip_is_idempotent() {
    let object = minimal_kyriotes_csk2_object();
    let encoded = encode_kyriotes_csk2_object(&object);
    let decoded = decode_kyriotes_csk2_object(&encoded).unwrap();
    let reencoded = encode_kyriotes_csk2_object(&decoded);

    assert_eq!(encoded, reencoded);
}

#[kani::proof]
fn encode_decode_roundtrip_binds_rights() {
    let mut object = minimal_kyriotes_csk2_object();
    object.required_rights = Rights::READ.union(Rights::DELEGATE);
    let encoded = encode_kyriotes_csk2_object(&object);
    let decoded = decode_kyriotes_csk2_object(&encoded).unwrap();

    assert_eq!(decoded.required_rights.bits(), object.required_rights.bits());
}

#[kani::proof]
fn encode_decode_roundtrip_binds_seal_epoch() {
    let mut object = minimal_kyriotes_csk2_object();
    object.seal_epoch = 42;
    let encoded = encode_kyriotes_csk2_object(&object);
    let decoded = decode_kyriotes_csk2_object(&encoded).unwrap();

    assert_eq!(decoded.seal_epoch, 42u64);
}

#[kani::proof]
fn encode_decode_roundtrip_binds_policy_hash() {
    let mut object = minimal_kyriotes_csk2_object();
    object.policy_hash[0] ^= 1;
    let encoded = encode_kyriotes_csk2_object(&object);
    let decoded = decode_kyriotes_csk2_object(&encoded).unwrap();

    assert_eq!(decoded.policy_hash[0], object.policy_hash[0]);
}
