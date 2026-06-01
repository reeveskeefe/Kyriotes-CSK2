#![cfg(kani)]
#![allow(dead_code)]

use crate::kyriotes_csk2::capability_tree::{
    CapabilityInclusionProof, CapabilityIssuanceProof, NonRevocationWitness,
};
use crate::kyriotes_csk2::engine::seal_with_verifier;
use crate::kyriotes_csk2::model::{
    AuthorityState, Capability, CapabilityProof, OpenRequest, RecipientPublicKey, TransparencyProof,
};
use crate::kyriotes_csk2::verify::{AuthorityVerifier, VerifiedAuthorityState};
use crate::{KyriotesCsk2Error, Rights, TemporalPolicy};

struct RejectingAuthorityVerifier;

impl AuthorityVerifier for RejectingAuthorityVerifier {
    fn verify_state(
        &self,
        _state: &AuthorityState,
        _transparency_proof: &TransparencyProof,
    ) -> Result<VerifiedAuthorityState, KyriotesCsk2Error> {
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

fn bytes64(seed: u8) -> [u8; 64] {
    let mut out = [0u8; 64];
    let mut i = 0usize;

    while i < 64 {
        out[i] = seed.wrapping_add(i as u8);
        i += 1;
    }

    out
}

fn minimal_recipient_pk() -> RecipientPublicKey {
    RecipientPublicKey {
        classical: x25519_dalek::PublicKey::from([9u8; 32]),
        pq: None,
    }
}

fn minimal_authority_state() -> AuthorityState {
    AuthorityState {
        authority_root: bytes32(11),
        revocation_root: bytes32(12),
        transparency_root: bytes32(13),
        epoch: 7,
        authority_id: "kani-authority".to_string(),
        root_pk: bytes32(14),
        revocation_count: 0,
        prev_epoch_hash: bytes32(15),
    }
}

fn minimal_transparency_proof() -> TransparencyProof {
    TransparencyProof {
        leaf_hash: bytes32(21),
        sibling_hashes: Vec::new(),
        leaf_index: 0,
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

fn minimal_open_request() -> OpenRequest {
    OpenRequest {
        object_id: "kani-object".to_string(),
        required_rights: Rights::READ,
        policy_hash: bytes32(31),
        epoch: 7,
    }
}

#[kani::proof]
fn seal_with_verifier_propagates_authority_rejection() {
    let verifier = RejectingAuthorityVerifier;
    let recipient_pk = minimal_recipient_pk();
    let message = [1u8, 2u8, 3u8];
    let capability = minimal_capability();
    let proof = minimal_capability_proof();
    let transparency_proof = minimal_transparency_proof();
    let state = minimal_authority_state();
    let request = minimal_open_request();

    let result = seal_with_verifier(
        &verifier,
        &recipient_pk,
        &message,
        &capability,
        &proof,
        &transparency_proof,
        &state,
        &request,
        TemporalPolicy::Current,
    );

    assert!(result.is_err());
}

#[kani::proof]
fn seal_with_verifier_rejection_is_deterministic() {
    let verifier = RejectingAuthorityVerifier;
    let recipient_pk = minimal_recipient_pk();
    let message = [1u8, 2u8, 3u8];
    let capability = minimal_capability();
    let proof = minimal_capability_proof();
    let transparency_proof = minimal_transparency_proof();
    let state = minimal_authority_state();
    let request = minimal_open_request();

    let first = seal_with_verifier(
        &verifier,
        &recipient_pk,
        &message,
        &capability,
        &proof,
        &transparency_proof,
        &state,
        &request,
        TemporalPolicy::Current,
    )
    .is_err();

    let second = seal_with_verifier(
        &verifier,
        &recipient_pk,
        &message,
        &capability,
        &proof,
        &transparency_proof,
        &state,
        &request,
        TemporalPolicy::Current,
    )
    .is_err();

    assert_eq!(first, second);
    assert!(first);
}

#[kani::proof]
fn seal_with_verifier_rejects_before_capability_validation_can_succeed() {
    let verifier = RejectingAuthorityVerifier;
    let recipient_pk = minimal_recipient_pk();
    let message = [1u8, 2u8, 3u8];
    let mut capability = minimal_capability();
    let proof = minimal_capability_proof();
    let transparency_proof = minimal_transparency_proof();
    let state = minimal_authority_state();
    let mut request = minimal_open_request();

    capability.object_id = "capability-object".to_string();
    request.object_id = "request-object".to_string();

    let result = seal_with_verifier(
        &verifier,
        &recipient_pk,
        &message,
        &capability,
        &proof,
        &transparency_proof,
        &state,
        &request,
        TemporalPolicy::Current,
    );

    assert!(result.is_err());
}

#[kani::proof]
fn seal_with_verifier_rejects_invalid_authority_surface_without_panic() {
    let verifier = RejectingAuthorityVerifier;
    let recipient_pk = minimal_recipient_pk();
    let message = [1u8, 2u8, 3u8];
    let capability = minimal_capability();
    let proof = minimal_capability_proof();
    let transparency_proof = minimal_transparency_proof();
    let mut state = minimal_authority_state();
    let request = minimal_open_request();

    state.transparency_root = [0u8; 32];

    let result = seal_with_verifier(
        &verifier,
        &recipient_pk,
        &message,
        &capability,
        &proof,
        &transparency_proof,
        &state,
        &request,
        TemporalPolicy::Current,
    );

    assert!(result.is_err());
}
