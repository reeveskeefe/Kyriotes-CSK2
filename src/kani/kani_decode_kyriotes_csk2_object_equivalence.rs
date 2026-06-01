#![cfg(kani)]
#![allow(dead_code)]

use crate::decode_kyriotes_csk2_object;

fn malformed_buffer_1() -> [u8; 1] {
    [0u8; 1]
}

fn malformed_buffer_2() -> [u8; 2] {
    [0x41u8, 0x52u8]
}

fn malformed_buffer_8() -> [u8; 8] {
    [
        0x41u8, 0x52u8, 0x43u8, 0x00u8, 0x01u8, 0x02u8, 0x03u8, 0x04u8,
    ]
}

fn malformed_buffer_32() -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut i = 0usize;

    while i < 32 {
        out[i] = i as u8;
        i += 1;
    }

    out
}

#[kani::proof]
fn decode_kyriotes_csk2_object_rejects_empty_input() {
    let input: [u8; 0] = [];
    let decoded = decode_kyriotes_csk2_object(&input);

    assert!(decoded.is_err());
}

#[kani::proof]
fn decode_kyriotes_csk2_object_rejects_one_byte_input() {
    let input = malformed_buffer_1();
    let decoded = decode_kyriotes_csk2_object(&input);

    assert!(decoded.is_err());
}

#[kani::proof]
fn decode_kyriotes_csk2_object_rejects_two_byte_input() {
    let input = malformed_buffer_2();
    let decoded = decode_kyriotes_csk2_object(&input);

    assert!(decoded.is_err());
}

#[kani::proof]
fn decode_kyriotes_csk2_object_rejects_tiny_malformed_input() {
    let input = malformed_buffer_8();
    let decoded = decode_kyriotes_csk2_object(&input);

    assert!(decoded.is_err());
}

#[kani::proof]
fn decode_kyriotes_csk2_object_rejects_bounded_malformed_input() {
    let input = malformed_buffer_32();
    let decoded = decode_kyriotes_csk2_object(&input);

    assert!(decoded.is_err());
}

#[kani::proof]
fn decode_kyriotes_csk2_object_malformed_rejection_is_deterministic() {
    let input = malformed_buffer_32();

    let first = decode_kyriotes_csk2_object(&input).is_err();
    let second = decode_kyriotes_csk2_object(&input).is_err();

    assert_eq!(first, second);
    assert!(first);
}
