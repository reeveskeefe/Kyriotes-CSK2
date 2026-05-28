/// Tests for the transparency log chain hash (`Log_e`, spec §8 / §25i)
/// and the `prev_epoch_hash` field on `AuthorityState`.
///
/// `Log_e = H(Log_{e-1} || R_e || Rev_e || e_le64 || pk_A_e || sigma_e)`
/// `Log_0 = H("ARC-LOG-GENESIS-v1" || R_0 || Rev_0 || 0_le64 || pk_A_0 || sigma_0)`
mod helpers;

use arc_core::{
    ArcError, AuthorityRootKeyPair, AuthorityVerifier, CryptoAuthorityVerifier,
    EpochSigningKeyPair, InMemoryTransparencyLog, TransparencyLog, transparency_log_entry_hash,
};
use helpers::state::sample_state;

// ---------------------------------------------------------------------------
// Determinism and structure
// ---------------------------------------------------------------------------

/// The genesis-epoch hash must be deterministic: same inputs → same output.
#[test]
fn chain_hash_genesis_is_deterministic() {
    let state = sample_state(0);
    let epoch_kp = EpochSigningKeyPair::from_seed([0xAAu8; 32]);
    let pk = epoch_kp.verifying_key_bytes();
    let sig = epoch_kp.sign_epoch_root(
        &state.authority_root,
        &state.revocation_root,
        &state.transparency_root,
        0,
        &[0u8; 32],
    );

    let h1 = transparency_log_entry_hash(
        &[0u8; 32],
        &state.authority_root,
        &state.revocation_root,
        0,
        &pk,
        &sig,
    );
    let h2 = transparency_log_entry_hash(
        &[0u8; 32],
        &state.authority_root,
        &state.revocation_root,
        0,
        &pk,
        &sig,
    );

    assert_eq!(h1, h2, "genesis hash must be deterministic");
    assert_ne!(h1, [0u8; 32], "genesis hash must be non-zero");
}

/// Changing `prev_hash` must change the resulting chain hash for epoch > 0.
#[test]
fn chain_hash_successive_epochs_link() {
    let state = sample_state(1);
    let epoch_kp = EpochSigningKeyPair::from_seed([0xBBu8; 32]);
    let pk = epoch_kp.verifying_key_bytes();

    let prev_a = [0u8; 32];
    let prev_b = [1u8; 32];

    let sig_a = epoch_kp.sign_epoch_root(
        &state.authority_root,
        &state.revocation_root,
        &state.transparency_root,
        1,
        &prev_a,
    );
    let sig_b = epoch_kp.sign_epoch_root(
        &state.authority_root,
        &state.revocation_root,
        &state.transparency_root,
        1,
        &prev_b,
    );

    let h_a = transparency_log_entry_hash(
        &prev_a,
        &state.authority_root,
        &state.revocation_root,
        1,
        &pk,
        &sig_a,
    );
    let h_b = transparency_log_entry_hash(
        &prev_b,
        &state.authority_root,
        &state.revocation_root,
        1,
        &pk,
        &sig_b,
    );

    assert_ne!(h_a, h_b, "different prev_hash must produce different Log_e");
}

/// Different epoch keys must produce different chain hashes even with the
/// same authority roots and epoch number.
#[test]
fn chain_hash_depends_on_epoch_key() {
    let state = sample_state(0);

    let kp1 = EpochSigningKeyPair::from_seed([0x01u8; 32]);
    let kp2 = EpochSigningKeyPair::from_seed([0x02u8; 32]);

    let pk1 = kp1.verifying_key_bytes();
    let pk2 = kp2.verifying_key_bytes();
    assert_ne!(pk1, pk2, "keypairs must differ");

    let sig1 = kp1.sign_epoch_root(
        &state.authority_root,
        &state.revocation_root,
        &state.transparency_root,
        0,
        &[0u8; 32],
    );
    let sig2 = kp2.sign_epoch_root(
        &state.authority_root,
        &state.revocation_root,
        &state.transparency_root,
        0,
        &[0u8; 32],
    );

    let h1 = transparency_log_entry_hash(
        &[0u8; 32],
        &state.authority_root,
        &state.revocation_root,
        0,
        &pk1,
        &sig1,
    );
    let h2 = transparency_log_entry_hash(
        &[0u8; 32],
        &state.authority_root,
        &state.revocation_root,
        0,
        &pk2,
        &sig2,
    );

    assert_ne!(h1, h2, "different epoch keys must produce different Log_e");
}

// ---------------------------------------------------------------------------
// CryptoAuthorityVerifier uses state.prev_epoch_hash
// ---------------------------------------------------------------------------

/// `CryptoAuthorityVerifier` must accept a state where `prev_epoch_hash`
/// matches what was used when signing `sigma_e`.
#[test]
fn verify_state_accepts_correct_prev_epoch_hash() {
    let prev_hash = [0x42u8; 32]; // non-zero, non-genesis

    let root_kp = AuthorityRootKeyPair::from_seed([0x11u8; 32]);
    let epoch_kp = EpochSigningKeyPair::from_seed([0x22u8; 32]);

    let mut state = sample_state(5);
    state.root_pk = root_kp.verifying_key_bytes();
    state.prev_epoch_hash = prev_hash;

    let epoch_pk = epoch_kp.verifying_key_bytes();
    let cert = root_kp.issue_epoch_cert(&epoch_pk, state.epoch, 10);

    let mut log = InMemoryTransparencyLog::new();
    let commit = log.commit_state(&state).expect("commit should succeed");

    // Sign sigma_e with the CORRECT prev_hash and the real transparency_root.
    let sig = epoch_kp.sign_epoch_root(
        &commit.state.authority_root,
        &commit.state.revocation_root,
        &commit.state.transparency_root,
        commit.state.epoch,
        &prev_hash,
    );

    let mut verifier = CryptoAuthorityVerifier::with_root_pk(root_kp.verifying_key_bytes());
    verifier.add_evidence(
        commit.state.authority_id.clone(),
        commit.state.epoch,
        epoch_pk,
        sig,
        cert,
    );

    // Verification must succeed because sigma_e was signed with the correct prev_hash
    // that matches state.prev_epoch_hash.
    verifier
        .verify_state(&commit.state, &commit.proof)
        .expect("verify_state must accept correct prev_epoch_hash");
}

/// `CryptoAuthorityVerifier` must REJECT a state where `sigma_e` was signed
/// with a different `prev_epoch_hash` than what is in `state.prev_epoch_hash`.
#[test]
fn verify_state_rejects_wrong_prev_epoch_hash() {
    let correct_prev = [0x42u8; 32];
    let wrong_prev = [0xFFu8; 32];

    let root_kp = AuthorityRootKeyPair::from_seed([0x33u8; 32]);
    let epoch_kp = EpochSigningKeyPair::from_seed([0x44u8; 32]);

    let mut state = sample_state(7);
    state.root_pk = root_kp.verifying_key_bytes();
    // State claims prev_epoch_hash = correct_prev.
    state.prev_epoch_hash = correct_prev;

    let epoch_pk = epoch_kp.verifying_key_bytes();
    let cert = root_kp.issue_epoch_cert(&epoch_pk, state.epoch, 10);

    let mut log = InMemoryTransparencyLog::new();
    let commit = log.commit_state(&state).expect("commit should succeed");

    // But sigma_e was actually signed with wrong_prev — mismatch.
    let sig = epoch_kp.sign_epoch_root(
        &commit.state.authority_root,
        &commit.state.revocation_root,
        &commit.state.transparency_root,
        commit.state.epoch,
        &wrong_prev,
    );

    let mut verifier = CryptoAuthorityVerifier::with_root_pk(root_kp.verifying_key_bytes());
    verifier.add_evidence(
        commit.state.authority_id.clone(),
        commit.state.epoch,
        epoch_pk,
        sig,
        cert,
    );

    let err = verifier
        .verify_state(&commit.state, &commit.proof)
        .expect_err("verify_state must reject mismatched prev_epoch_hash");

    assert!(
        matches!(err, ArcError::AuthorityState(_)),
        "expected AuthorityState error, got {err:?}"
    );
}
