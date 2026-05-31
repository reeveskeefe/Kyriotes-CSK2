#![cfg(kani)]
#![allow(dead_code)]

use crate::ArcError;
use crate::arc::engine::begin_epoch_rotation_commit;
use crate::arc::model::{AuthorityState, TransparencyProof};
use crate::arc::transparency::{TransparencyLog, TransparencyStateCommit};

struct RejectingTransparencyLog {
    store_chain_hash_called: bool,
}

impl RejectingTransparencyLog {
    fn new() -> Self {
        Self {
            store_chain_hash_called: false,
        }
    }
}

impl TransparencyLog for RejectingTransparencyLog {
    fn commit_state(
        &mut self,
        _state: &AuthorityState,
    ) -> Result<TransparencyStateCommit, ArcError> {
        Err(ArcError::Parse("kani rejecting transparency log"))
    }

    fn proof_for_state(&self, _state: &AuthorityState) -> Result<TransparencyProof, ArcError> {
        Err(ArcError::Parse("kani rejecting transparency proof"))
    }

    fn current_root(&self) -> [u8; 32] {
        [0u8; 32]
    }

    fn store_chain_hash(&mut self, _authority_id: &str, _epoch: u64, _chain_hash: [u8; 32]) {
        self.store_chain_hash_called = true;
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

fn authority_state() -> AuthorityState {
    AuthorityState {
        authority_root: bytes32(11),
        revocation_root: bytes32(12),
        transparency_root: [0u8; 32],
        epoch: 8,
        authority_id: "kani-authority".to_string(),
        epoch_signature_valid: true,
        epoch_key_cert_valid: true,
        transparency_inclusion_valid: true,
        root_pk: bytes32(14),
        revocation_count: 42,
        prev_epoch_hash: bytes32(15),
    }
}

#[kani::proof]
fn rotate_epoch_full_commit_phase_propagates_transparency_commit_rejection() {
    let mut log = RejectingTransparencyLog::new();
    let state = authority_state();

    let result = begin_epoch_rotation_commit(&mut log, &state);

    assert!(result.is_err());
}

#[kani::proof]
fn rotate_epoch_full_commit_phase_rejection_is_deterministic() {
    let state = authority_state();

    let mut first_log = RejectingTransparencyLog::new();
    let mut second_log = RejectingTransparencyLog::new();

    let first = begin_epoch_rotation_commit(&mut first_log, &state).is_err();
    let second = begin_epoch_rotation_commit(&mut second_log, &state).is_err();

    assert_eq!(first, second);
    assert!(first);
}

#[kani::proof]
fn rotate_epoch_full_commit_phase_does_not_store_chain_hash_when_commit_fails() {
    let mut log = RejectingTransparencyLog::new();
    let state = authority_state();

    let result = begin_epoch_rotation_commit(&mut log, &state);

    assert!(result.is_err());
    assert!(!log.store_chain_hash_called);
}

#[kani::proof]
fn rotate_epoch_full_commit_phase_rejection_hides_commit_material() {
    let mut log = RejectingTransparencyLog::new();
    let state = authority_state();

    let result = begin_epoch_rotation_commit(&mut log, &state);

    match result {
        Ok(_) => assert!(false),
        Err(_) => assert!(true),
    }
}
