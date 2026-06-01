#![cfg(kani)]
#![allow(dead_code)]

use crate::kyriotes_csk2::capability_tree::{
    CapabilityInclusionProof, CapabilityIssuanceProof, NonRevocationWitness,
};
use crate::kyriotes_csk2::engine::open_with_verifier;
use crate::kyriotes_csk2::model::{
    AuthorityState, AuthorityWrapper, Capability, CapabilityProof, KyriotesCsk2Object,
    RecipientSecretKey, TransparencyProof,
};
use crate::kyriotes_csk2::verify::AuthorityVerifier;
use crate::{KyriotesCsk2Error, Rights, TemporalPolicy};

struct RejectingAuthorityVerifier;

impl AuthorityVerifier for RejectingAuthorityVerifier {
    fn verify_state(
        &self,
        _state: &AuthorityState,
        _transparency_proof: &TransparencyProof,
    ) -> Result<(), KyriotesCsk2Error> {
        Err(KyriotesCsk2Error::Parse(
            "kani rejecting authority verifier",
        ))
    }
}

fn bytes32(seed: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut i = 0usize;

    while i < 32 {
        out[i] = seed.wrapping_add(i as u8);
        i += 1;
    }

    out
}

fn bytes16(seed: u8) -> [u8; 16] {
    let mut out = [0u8; 16];
    let mut i = 0usize;

    while i < 16 {
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

fn bytes64(seed: u8) -> [u8; 64] {
    let mut out = [0u8; 64];
    let mut i = 0usize;

    while i < 64 {
        out[i] = seed.wrapping_add(i as u8);
        i += 1;
    }

    out
}

fn minimal_recipient_sk() -> RecipientSecretKey {
    RecipientSecretKey {
        classical: x25519_dalek::StaticSecret::from([7u8; 32]),
        pq: None,
    }
}

fn minimal_transparency_proof() -> TransparencyProof {
    TransparencyProof {
        leaf_hash: bytes32(21),
        sibling_hashes: Vec::new(),
        leaf_index: 0,
    }
}

fn minimal_authority_wrapper() -> AuthorityWrapper {
    AuthorityWrapper {
        epoch: 7,
        kem_ct_classical: bytes32(31),
        kem_ct_pq: Vec::new(),
        wrap_nonce: bytes12(33),
        wrapped_dek: vec![4u8, 5u8, 6u8],
        context_hash: bytes32(34),
        capability_stamp: bytes32(35),
        transparency_proof: minimal_transparency_proof(),
    }
}

fn minimal_authority_state() -> AuthorityState {
    AuthorityState {
        authority_root: bytes32(11),
        revocation_root: bytes32(12),
        transparency_root: bytes32(13),
        epoch: 7,
        authority_id: "kani-authority".to_string(),
        epoch_signature_valid: true,
        epoch_key_cert_valid: true,
        transparency_inclusion_valid: true,
        root_pk: bytes32(14),
        revocation_count: 0,
        prev_epoch_hash: bytes32(15),
    }
}

fn minimal_capability() -> Capability {
    Capability {
        version: 1,
        subject: "kani-subject".to_string(),
        object_id: "kani-object".to_string(),
        rights: Rights::READ,
        policy_hash: bytes32(31),
        epoch_start: 1,
        epoch_end: 10,
        delegation_depth: 0,
        parent_stamp: [0u8; 32],
        nonce: bytes16(41),
    }
}

fn minimal_capability_proof() -> CapabilityProof {
    CapabilityProof {
        inclusion: CapabilityInclusionProof {
            leaf_hash: bytes32(51),
            sibling_hashes: Vec::new(),
            leaf_index: 0,
        },
        non_revocation: NonRevocationWitness {
            stamp: bytes32(61),
            total_revoked: 0,
            left: None,
            right: None,
        },
        issuance: CapabilityIssuanceProof {
            sig: bytes64(71),
            epoch_cert: crate::kyriotes_csk2::authority::EpochKeyCert {
                epoch_pk: bytes32(81),
                epoch: 7,
                validity_window: 1,
                signature: bytes64(91),
            },
        },
    }
}

fn minimal_arc_object() -> KyriotesCsk2Object {
    KyriotesCsk2Object {
        version: 1,
        suite: "KYRIOTES-CSK2-KANI-SUITE".to_string(),
        object_id: "kani-object".to_string(),
        required_rights: Rights::READ,
        policy_hash: bytes32(31),
        seal_epoch: 7,
        temporal_policy: TemporalPolicy::Current,
        authority_root: bytes32(11),
        revocation_root: bytes32(12),
        payload_nonce: bytes12(101),
        payload_ciphertext: vec![1u8, 2u8, 3u8],
        wrappers: vec![minimal_authority_wrapper()],
    }
}

#[kani::proof]
fn open_with_verifier_propagates_authority_rejection() {
    let verifier = RejectingAuthorityVerifier;
    let recipient_sk = minimal_recipient_sk();
    let object = minimal_arc_object();
    let capability = minimal_capability();
    let proof = minimal_capability_proof();
    let state = minimal_authority_state();

    let result = open_with_verifier(
        &verifier,
        &recipient_sk,
        &object,
        &capability,
        &proof,
        &state,
    );

    assert!(result.is_err());
}

#[kani::proof]
fn open_with_verifier_rejection_is_deterministic() {
    let verifier = RejectingAuthorityVerifier;
    let recipient_sk = minimal_recipient_sk();
    let object = minimal_arc_object();
    let capability = minimal_capability();
    let proof = minimal_capability_proof();
    let state = minimal_authority_state();

    let first = open_with_verifier(
        &verifier,
        &recipient_sk,
        &object,
        &capability,
        &proof,
        &state,
    )
    .is_err();

    let second = open_with_verifier(
        &verifier,
        &recipient_sk,
        &object,
        &capability,
        &proof,
        &state,
    )
    .is_err();

    assert_eq!(first, second);
    assert!(first);
}

#[kani::proof]
fn open_with_verifier_rejects_before_capability_validation_can_succeed() {
    let verifier = RejectingAuthorityVerifier;
    let recipient_sk = minimal_recipient_sk();
    let mut object = minimal_arc_object();
    let mut capability = minimal_capability();
    let proof = minimal_capability_proof();
    let state = minimal_authority_state();

    object.object_id = "object-a".to_string();
    capability.object_id = "object-b".to_string();

    let result = open_with_verifier(
        &verifier,
        &recipient_sk,
        &object,
        &capability,
        &proof,
        &state,
    );

    assert!(result.is_err());
}

#[kani::proof]
fn open_with_verifier_rejects_invalid_authority_surface_without_panic() {
    let verifier = RejectingAuthorityVerifier;
    let recipient_sk = minimal_recipient_sk();
    let object = minimal_arc_object();
    let capability = minimal_capability();
    let proof = minimal_capability_proof();
    let mut state = minimal_authority_state();

    state.epoch_signature_valid = false;
    state.epoch_key_cert_valid = false;
    state.transparency_inclusion_valid = false;

    let result = open_with_verifier(
        &verifier,
        &recipient_sk,
        &object,
        &capability,
        &proof,
        &state,
    );

    assert!(result.is_err());
}
