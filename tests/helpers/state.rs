#![allow(dead_code)]

use kyriotes_csk2::AuthorityState;

pub fn sample_state(epoch: u64) -> AuthorityState {
    AuthorityState {
        authority_root: [epoch as u8; 32],
        revocation_root: [(epoch as u8).wrapping_add(1); 32],
        transparency_root: [0u8; 32],
        epoch,
        authority_id: "auth-main".to_string(),
        root_pk: [0u8; 32],
        revocation_count: 0,
        prev_epoch_hash: [0u8; 32],
    }
}
