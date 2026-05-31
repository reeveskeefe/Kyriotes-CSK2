#![cfg(kani)]
#![allow(dead_code)]

use crate::arc::capability_tree::{
    CapabilityInclusionProof, CapabilityIssuanceProof, NonRevocationWitness,
};
use crate::arc::engine::add_epoch_wrapper_with_verifier;
use crate::arc::model::{
    ArcObject, AuthorityState, AuthorityWrapper, Capability, CapabilityProof, RecipientPublicKey,
    RecipientSecretKey, TransparencyProof,
};
use crate::arc::verify::AuthorityVerifier;
use crate::{ArcError, Rights, TemporalPolicy};

struct RejectingAuthorityVerifier;

impl AuthorityVerifier for RejectingAuthorityVerifier {
    fn verify_state(
        &self,
        _state: &AuthorityState,
        _transparency_proof: &TransparencyProof,
    ) -> Result<(), ArcError> {
        Err(ArcError::Parse("kani rejecting authority verifier"))
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

fn minimal_recipient_pk() -> RecipientPublicKey {
    RecipientPublicKey {
        classical: x25519_dalek::PublicKey::from([9u8; 32]),
        pq: None,
    }
}

fn transparency_proof(seed: u8) -> TransparencyProof {
    TransparencyProof {
        leaf_hash: bytes32(seed),
        sibling_hashes: Vec::new(),
        leaf_index: 0,
    }
}

fn authority_state(epoch: u64, seed: u8) -> AuthorityState {
    AuthorityState {
        authority_root: bytes32(seed),
        revocation_root: bytes32(seed.wrapping_add(1)),
        transparency_root: bytes32(seed.wrapping_add(2)),
        epoch,
        authority_id: "kani-authority".to_string(),
        epoch_signature_valid: true,
        epoch_key_cert_valid: true,
        transparency_inclusion_valid: true,
        root_pk: bytes32(seed.wrapping_add(3)),
        revocation_count: 0,
        prev_epoch_hash: bytes32(seed.wrapping_add(4)),
    }
}

fn authority_wrapper(epoch: u64, seed: u8) -> AuthorityWrapper {
    AuthorityWrapper {
        epoch,
        kem_ct_classical: bytes32(seed),
        kem_ct_pq: Vec::new(),
        wrap_nonce: bytes12(seed.wrapping_add(1)),
        wrapped_dek: vec![4u8, 5u8, 6u8],
        context_hash: bytes32(seed.wrapping_add(2)),
        capability_stamp: bytes32(seed.wrapping_add(3)),
        transparency_proof: transparency_proof(seed.wrapping_add(4)),
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
            epoch_cert: crate::arc::authority::EpochKeyCert {
                epoch_pk: bytes32(81),
                epoch: 7,
                validity_window: 1,
                signature: bytes64(91),
            },
        },
    }
}

fn minimal_arc_object() -> ArcObject {
    ArcObject {
        version: 1,
        suite: "ARC-KANI-SUITE".to_string(),
        object_id: "kani-object".to_string(),
        required_rights: Rights::READ,
        policy_hash: bytes32(31),
        seal_epoch: 7,
        temporal_policy: TemporalPolicy::Current,
        authority_root: bytes32(11),
        revocation_root: bytes32(12),
        payload_nonce: bytes12(101),
        payload_ciphertext: vec![1u8, 2u8, 3u8],
        wrappers: vec![authority_wrapper(7, 111)],
    }
}

#[kani::proof]
fn add_epoch_wrapper_with_verifier_propagates_from_authority_rejection() {
    let verifier = RejectingAuthorityVerifier;
    let recipient_sk = minimal_recipient_sk();
    let recipient_pk = minimal_recipient_pk();
    let mut object = minimal_arc_object();
    let capability = minimal_capability();
    let proof = minimal_capability_proof();
    let from_state = authority_state(7, 11);
    let to_state = authority_state(8, 21);
    let to_transparency_proof = transparency_proof(31);

    let result = add_epoch_wrapper_with_verifier(
        &verifier,
        &recipient_sk,
        &recipient_pk,
        &mut object,
        &capability,
        &proof,
        &from_state,
        &to_state,
        &to_transparency_proof,
    );

    assert!(result.is_err());
}

#[kani::proof]
fn add_epoch_wrapper_with_verifier_rejection_is_deterministic() {
    let verifier = RejectingAuthorityVerifier;
    let recipient_sk = minimal_recipient_sk();
    let recipient_pk = minimal_recipient_pk();
    let capability = minimal_capability();
    let proof = minimal_capability_proof();
    let from_state = authority_state(7, 11);
    let to_state = authority_state(8, 21);
    let to_transparency_proof = transparency_proof(31);

    let mut first_object = minimal_arc_object();
    let mut second_object = minimal_arc_object();

    let first = add_epoch_wrapper_with_verifier(
        &verifier,
        &recipient_sk,
        &recipient_pk,
        &mut first_object,
        &capability,
        &proof,
        &from_state,
        &to_state,
        &to_transparency_proof,
    )
    .is_err();

    let second = add_epoch_wrapper_with_verifier(
        &verifier,
        &recipient_sk,
        &recipient_pk,
        &mut second_object,
        &capability,
        &proof,
        &from_state,
        &to_state,
        &to_transparency_proof,
    )
    .is_err();

    assert_eq!(first, second);
    assert!(first);
}

#[kani::proof]
fn add_epoch_wrapper_with_verifier_rejects_before_capability_validation_can_succeed() {
    let verifier = RejectingAuthorityVerifier;
    let recipient_sk = minimal_recipient_sk();
    let recipient_pk = minimal_recipient_pk();
    let mut object = minimal_arc_object();
    let mut capability = minimal_capability();
    let proof = minimal_capability_proof();
    let from_state = authority_state(7, 11);
    let to_state = authority_state(8, 21);
    let to_transparency_proof = transparency_proof(31);

    object.object_id = "object-a".to_string();
    capability.object_id = "object-b".to_string();

    let result = add_epoch_wrapper_with_verifier(
        &verifier,
        &recipient_sk,
        &recipient_pk,
        &mut object,
        &capability,
        &proof,
        &from_state,
        &to_state,
        &to_transparency_proof,
    );

    assert!(result.is_err());
}

#[kani::proof]
fn add_epoch_wrapper_with_verifier_does_not_change_wrapper_count_on_rejection() {
    let verifier = RejectingAuthorityVerifier;
    let recipient_sk = minimal_recipient_sk();
    let recipient_pk = minimal_recipient_pk();
    let mut object = minimal_arc_object();
    let capability = minimal_capability();
    let proof = minimal_capability_proof();
    let from_state = authority_state(7, 11);
    let to_state = authority_state(8, 21);
    let to_transparency_proof = transparency_proof(31);

    let before = object.wrappers.len();

    let result = add_epoch_wrapper_with_verifier(
        &verifier,
        &recipient_sk,
        &recipient_pk,
        &mut object,
        &capability,
        &proof,
        &from_state,
        &to_state,
        &to_transparency_proof,
    );

    let after = object.wrappers.len();

    assert!(result.is_err());
    assert_eq!(before, after);
}
