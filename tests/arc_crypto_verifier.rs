mod helpers;

use arc_core::{
    ArcError,
    AuthorityRootKeyPair,
    CryptoAuthorityVerifier,
    EpochSigningKeyPair,
    InMemoryTransparencyLog,
    TransparencyLog,
    open_with_verifier,
    seal_with_verifier,
};
use helpers::scenario::Scenario;
use helpers::state::sample_state;

/// Build a `CryptoAuthorityVerifier` wired up with a real offline-root →
/// epoch-key cert chain for the given `state`.
///
/// `root_seed` and `epoch_seed` are deterministic 32-byte seeds so tests are
/// reproducible.  They must differ to ensure the two keypairs are distinct.
fn signed_verifier_for_state(
    state: &arc_core::AuthorityState,
    root_seed: u8,
    epoch_seed: u8,
) -> CryptoAuthorityVerifier {
    let root_kp = AuthorityRootKeyPair::from_seed([root_seed; 32]);
    let epoch_kp = EpochSigningKeyPair::from_seed([epoch_seed; 32]);

    let epoch_pk = epoch_kp.verifying_key_bytes();
    let cert = root_kp.issue_epoch_cert(&epoch_pk, state.epoch, 10);
    let epoch_root_sig = epoch_kp.sign_epoch_root(
        &state.authority_root,
        &state.revocation_root,
        state.epoch,
        &[0u8; 32], // genesis prev_epoch_hash
    );

    let mut verifier = CryptoAuthorityVerifier::with_root_pk(root_kp.verifying_key_bytes());
    verifier.add_evidence(
        state.authority_id.clone(),
        state.epoch,
        epoch_pk,
        epoch_root_sig,
        cert,
    );
    verifier
}

#[test]
fn seal_open_with_crypto_verifier_success() {
    let s = Scenario::baseline("strict", 42)
        .with_message(b"signed-authority-path");

    let verifier = signed_verifier_for_state(&s.seal_state, 13, 14);

    let object = seal_with_verifier(
        &verifier,
        &s.keypair.public,
        &s.message,
        &s.cap,
        &s.proof,
        &s.seal_transparency_proof,
        &s.seal_state,
        &s.req,
        s.temporal_policy.clone(),
    )
    .expect("seal with crypto verifier should succeed");

    let opened = open_with_verifier(
        &verifier,
        &s.keypair.secret,
        &object,
        &s.cap,
        &s.proof,
        &s.open_state,
    )
    .expect("open with crypto verifier should succeed");

    assert_eq!(opened, b"signed-authority-path");
}

#[test]
fn open_with_crypto_verifier_rejects_tampered_authority_state() {
    let s = Scenario::baseline("strict", 42)
        .with_message(b"tamper-test");

    let verifier = signed_verifier_for_state(&s.seal_state, 21, 22);

    let object = seal_with_verifier(
        &verifier,
        &s.keypair.public,
        &s.message,
        &s.cap,
        &s.proof,
        &s.seal_transparency_proof,
        &s.seal_state,
        &s.req,
        s.temporal_policy.clone(),
    )
    .expect("seal should succeed");

    let mut tampered_state = s.open_state.clone();
    tampered_state.authority_root[0] ^= 0xFF;

    let err = open_with_verifier(
        &verifier,
        &s.keypair.secret,
        &object,
        &s.cap,
        &s.proof,
        &tampered_state,
    )
    .expect_err("tampered authority state must be rejected");

    assert!(matches!(err, ArcError::AuthorityState("epoch root signature invalid")));
}

#[test]
fn open_with_crypto_verifier_rejects_malformed_sibling_ordering() {
    let mut s = Scenario::baseline("strict", 42)
        .with_message(b"malformed-proof-order");

    let mut log = InMemoryTransparencyLog::new();
    for i in 0..3u64 {
        let mut filler = sample_state(300 + i);
        filler.authority_id = format!("filler-{i}");
        log.commit_state(&filler)
            .expect("filler state should commit");
    }

    let target_commit = log
        .commit_state(&s.seal_state)
        .expect("target state should commit");
    assert!(
        target_commit.proof.sibling_hashes.len() >= 2,
        "test requires multi-level proof"
    );

    s.seal_state = target_commit.state.clone();
    s.open_state = target_commit.state.clone();
    s.seal_transparency_proof = target_commit.proof.clone();
    s.open_transparency_proof = target_commit.proof.clone();

    let verifier = signed_verifier_for_state(&s.seal_state, 31, 32);

    let mut object = seal_with_verifier(
        &verifier,
        &s.keypair.public,
        &s.message,
        &s.cap,
        &s.proof,
        &s.seal_transparency_proof,
        &s.seal_state,
        &s.req,
        s.temporal_policy.clone(),
    )
    .expect("seal should succeed");

    object.wrappers[0].transparency_proof.sibling_hashes.reverse();

    let err = open_with_verifier(
        &verifier,
        &s.keypair.secret,
        &object,
        &s.cap,
        &s.proof,
        &s.open_state,
    )
    .expect_err("malformed sibling order should fail transparency verification");

    assert!(matches!(
        err,
        ArcError::AuthorityState("transparency proof root mismatch")
    ));
}
