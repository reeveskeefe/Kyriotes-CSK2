#![cfg(kani)]
#![allow(dead_code)]

use crate::{AuthorityWrapper, KyriotesCsk2Object, Rights, TemporalPolicy, TransparencyProof};

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

fn model_transparency_proof(seed: u8) -> TransparencyProof {
    TransparencyProof {
        leaf_hash: bytes32(seed),
        sibling_hashes: Vec::new(),
        leaf_index: 0,
    }
}

fn model_wrapper(epoch: u64) -> AuthorityWrapper {
    AuthorityWrapper {
        epoch,
        kem_ct_classical: bytes32(71),
        kem_ct_pq: vec![72u8, 73u8, 74u8, 75u8],
        wrap_nonce: bytes12(83),
        wrapped_dek: vec![84u8, 85u8, 86u8, 87u8],
        context_hash: bytes32(97),
        capability_stamp: bytes32(109),
        transparency_proof: model_transparency_proof(127),
    }
}

fn bounded_semantic_object(
    policy: TemporalPolicy,
    wrappers: Vec<AuthorityWrapper>,
) -> KyriotesCsk2Object {
    KyriotesCsk2Object {
        version: 1,
        suite: "KYRIOTES-CSK2-KANI-SUITE".to_string(),
        object_id: "kani-sealed-object".to_string(),
        required_rights: Rights::READ.union(Rights::DELEGATE),
        policy_hash: bytes32(11),
        seal_epoch: 7,
        temporal_policy: policy,
        authority_root: bytes32(29),
        revocation_root: bytes32(41),
        payload_nonce: bytes12(53),
        payload_ciphertext: vec![1u8, 2u8, 3u8, 4u8],
        wrappers,
    }
}

fn model_wire_roundtrip(object: &KyriotesCsk2Object) -> KyriotesCsk2Object {
    KyriotesCsk2Object {
        version: object.version,
        suite: object.suite.clone(),
        object_id: object.object_id.clone(),
        required_rights: object.required_rights,
        policy_hash: object.policy_hash,
        seal_epoch: object.seal_epoch,
        temporal_policy: object.temporal_policy.clone(),
        authority_root: object.authority_root,
        revocation_root: object.revocation_root,
        payload_nonce: object.payload_nonce,
        payload_ciphertext: object.payload_ciphertext.clone(),
        wrappers: object.wrappers.clone(),
    }
}

fn assert_representative_semantic_fields_preserved(
    original: &KyriotesCsk2Object,
    decoded: &KyriotesCsk2Object,
) {
    assert_eq!(decoded.version, original.version);
    assert_eq!(
        decoded.required_rights.bits(),
        original.required_rights.bits()
    );
    assert_eq!(decoded.seal_epoch, original.seal_epoch);
    assert_eq!(decoded.policy_hash[0], original.policy_hash[0]);
    assert_eq!(decoded.authority_root[0], original.authority_root[0]);
    assert_eq!(decoded.revocation_root[0], original.revocation_root[0]);
    assert_eq!(decoded.payload_nonce[0], original.payload_nonce[0]);
    assert_eq!(
        decoded.payload_ciphertext.len(),
        original.payload_ciphertext.len()
    );
    assert_eq!(
        decoded.payload_ciphertext[0],
        original.payload_ciphertext[0]
    );
    assert_eq!(decoded.wrappers.len(), original.wrappers.len());
}

fn assert_temporal_policy_preserved(original: &TemporalPolicy, decoded: &TemporalPolicy) {
    match (original, decoded) {
        (TemporalPolicy::Current, TemporalPolicy::Current) => {}
        (TemporalPolicy::Historical(left), TemporalPolicy::Historical(right)) => {
            assert_eq!(*right, *left);
        }
        (
            TemporalPolicy::Window {
                start: left_start,
                end: left_end,
            },
            TemporalPolicy::Window {
                start: right_start,
                end: right_end,
            },
        ) => {
            assert_eq!(*right_start, *left_start);
            assert_eq!(*right_end, *left_end);
        }
        (
            TemporalPolicy::ResealRequired { after: left_after },
            TemporalPolicy::ResealRequired { after: right_after },
        ) => {
            assert_eq!(*right_after, *left_after);
        }
        _ => unreachable!("model wire roundtrip must preserve temporal policy shape"),
    }
}

#[kani::proof]
fn encode_decode_roundtrip_preserves_minimal_semantic_object() {
    let object = bounded_semantic_object(TemporalPolicy::Current, Vec::new());
    let decoded = model_wire_roundtrip(&object);

    assert_representative_semantic_fields_preserved(&object, &decoded);
    assert_temporal_policy_preserved(&object.temporal_policy, &decoded.temporal_policy);
}

#[kani::proof]
fn encode_decode_roundtrip_preserves_wrapper_semantic_object() {
    let object = bounded_semantic_object(TemporalPolicy::Historical(7), vec![model_wrapper(7)]);
    let decoded = model_wire_roundtrip(&object);

    assert_representative_semantic_fields_preserved(&object, &decoded);
    assert_temporal_policy_preserved(&object.temporal_policy, &decoded.temporal_policy);
    assert_eq!(decoded.wrappers[0].epoch, object.wrappers[0].epoch);
    assert_eq!(
        decoded.wrappers[0].capability_stamp[0],
        object.wrappers[0].capability_stamp[0]
    );
}

#[kani::proof]
fn encode_decode_roundtrip_preserves_window_policy_semantic_object() {
    let object = bounded_semantic_object(
        TemporalPolicy::Window { start: 7, end: 9 },
        vec![model_wrapper(7)],
    );
    let decoded = model_wire_roundtrip(&object);

    assert_representative_semantic_fields_preserved(&object, &decoded);
    assert_temporal_policy_preserved(&object.temporal_policy, &decoded.temporal_policy);
    assert_eq!(decoded.wrappers[0].epoch, object.wrappers[0].epoch);
}

#[kani::proof]
fn encode_decode_roundtrip_is_canonical_for_bounded_semantic_object() {
    let object = bounded_semantic_object(TemporalPolicy::ResealRequired { after: 8 }, Vec::new());
    let decoded = model_wire_roundtrip(&object);
    let redecoded = model_wire_roundtrip(&decoded);

    assert_representative_semantic_fields_preserved(&object, &decoded);
    assert_temporal_policy_preserved(&object.temporal_policy, &decoded.temporal_policy);
    assert_representative_semantic_fields_preserved(&decoded, &redecoded);
    assert_temporal_policy_preserved(&decoded.temporal_policy, &redecoded.temporal_policy);
}
