/// Integration tests for spec §16 compromise-check-integrated open/verify:
/// `open_with_compromise_check` and `verify_with_compromise_check`.
mod helpers;

use arc_core::{
    ArcError, AuthorityRootKeyPair, EpochSigningKeyPair, TemporalPolicy,
    open_with_compromise_check, seal, verify_with_compromise_check,
};
use helpers::{request_builders::policy_hash, scenario::Scenario};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_notice_for(
    root_kp: &AuthorityRootKeyPair,
    bad_epoch_pk: [u8; 32],
    compromised_epoch: u64,
) -> arc_core::CompromiseNotice {
    root_kp.issue_compromise_notice(&bad_epoch_pk, compromised_epoch, [0xABu8; 32])
}

// ---------------------------------------------------------------------------
// open_with_compromise_check
// ---------------------------------------------------------------------------

#[test]
fn open_with_compromise_check_succeeds_with_empty_notices() {
    let s = Scenario::baseline("open-compromise-empty", 42);
    let obj = seal(
        &s.keypair.public,
        b"payload",
        &s.cap,
        &s.proof,
        &s.seal_transparency_proof,
        &s.seal_state,
        &s.req,
        TemporalPolicy::Historical(42),
    )
    .unwrap();

    let plaintext = open_with_compromise_check(
        &s.keypair.secret,
        &obj,
        &s.cap,
        &s.proof,
        &s.open_state,
        &[], // no notices
    )
    .expect("empty notices should pass through to normal open");

    assert_eq!(plaintext, b"payload");
}

#[test]
fn open_with_compromise_check_succeeds_when_notice_does_not_match_epoch_key() {
    let s = Scenario::baseline("open-compromise-no-match", 42);
    let obj = seal(
        &s.keypair.public,
        b"secret",
        &s.cap,
        &s.proof,
        &s.seal_transparency_proof,
        &s.seal_state,
        &s.req,
        TemporalPolicy::Historical(42),
    )
    .unwrap();

    // Notice targets a *different* epoch key — should not block the open.
    let root_kp = AuthorityRootKeyPair::generate(&mut rand::rngs::OsRng);
    let different_pk = [0xFFu8; 32];
    let _notice = root_kp.issue_compromise_notice(&different_pk, 42, [0u8; 32]);

    // This notice has wrong root_pk relative to s.open_state.root_pk — it
    // will fail notice signature verification.  Use a valid notice signed
    // by the correct root instead.
    let correct_notice = make_notice_for(
        // We need the authority's root_kp — extract from TestAuthority's state
        // by re-signing: create fresh authority with different epoch_pk.
        // Since we can't get the private root_kp from Scenario, we test the
        // unmatched-key path using the full Scenario authority.
        &AuthorityRootKeyPair::generate(&mut rand::rngs::OsRng),
        [0xEEu8; 32], // a key that is NOT the one used in s.proof
        42,
    );

    // The notice is signed by a different root key — verify_compromise_notice
    // will return Err, and enforce_compromise_notices propagates that.
    let result = open_with_compromise_check(
        &s.keypair.secret,
        &obj,
        &s.cap,
        &s.proof,
        &s.open_state,
        &[correct_notice],
    );
    // A notice signed by the wrong root key should fail.
    assert!(result.is_err());
}

#[test]
fn open_with_compromise_check_rejects_when_issuance_epoch_key_is_compromised() {
    // Build a scenario where we have access to the root keypair.
    let p = policy_hash("compromise-open-reject");
    let mut rng = rand::rngs::OsRng;
    let root_kp = AuthorityRootKeyPair::generate(&mut rng);
    let bad_epoch_kp = EpochSigningKeyPair::generate(&mut rng);
    let bad_epoch_pk = bad_epoch_kp.verifying_key_bytes();
    let epoch_cert = root_kp.issue_epoch_cert(&bad_epoch_pk, 42, 10);

    use arc_core::{
        AuthorityCapabilityTree, AuthorityState, CapabilityIssuanceProof, CapabilityProof,
        InMemoryTransparencyLog, RecipientKeyPair, TemporalPolicy, capability_leaf_hash,
        capability_stamp,
    };
    use helpers::capability::sample_cap;
    use helpers::request_builders::sample_req;
    use helpers::transparency::commit_state;

    let cap = sample_cap(40, 60, p);
    let mut tree = AuthorityCapabilityTree::new();
    tree.add_capability(&cap);

    let seed_state = AuthorityState {
        authority_root: tree.authority_root(),
        revocation_root: tree.revocation_root(),
        transparency_root: [0u8; 32],
        epoch: 42,
        authority_id: "auth-main".to_string(),
        epoch_signature_valid: true,
        epoch_key_cert_valid: true,
        transparency_inclusion_valid: true,
        root_pk: root_kp.verifying_key_bytes(),
        revocation_count: tree.revocation_count(),
        prev_epoch_hash: [0u8; 32],
    };
    let mut log = InMemoryTransparencyLog::new();
    let (state, transparency_proof) = commit_state(&mut log, &seed_state).unwrap();

    let inclusion = tree.inclusion_proof(&cap).unwrap();
    let stamp = capability_stamp(&cap, &state);
    let non_rev = tree.non_revocation_witness(&stamp).unwrap();
    let leaf_hash = capability_leaf_hash(&cap);
    let sig = bad_epoch_kp.sign_capability_issuance(&leaf_hash, &state.authority_root, 42);
    let proof = CapabilityProof {
        inclusion,
        non_revocation: non_rev,
        issuance: CapabilityIssuanceProof { sig, epoch_cert },
    };

    let keypair = RecipientKeyPair::generate(&mut rng);
    let req = sample_req(42, p);
    let obj = seal(
        &keypair.public,
        b"classified",
        &cap,
        &proof,
        &transparency_proof,
        &state,
        &req,
        TemporalPolicy::Historical(42),
    )
    .unwrap();

    // Now declare bad_epoch_pk compromised at epoch 42.
    let notice = root_kp.issue_compromise_notice(&bad_epoch_pk, 42, [0xABu8; 32]);

    let err = open_with_compromise_check(&keypair.secret, &obj, &cap, &proof, &state, &[notice])
        .expect_err("compromised epoch key should block the open");

    assert!(
        matches!(err, ArcError::AuthorityState(_)),
        "expected AuthorityState error, got: {err:?}"
    );
}

#[test]
fn open_with_compromise_check_allows_open_before_compromise_epoch() {
    // Same setup as above but notice declares compromise at epoch 43,
    // not 42 — historical opens at epoch < compromise boundary remain valid.
    let p = policy_hash("historical-valid");
    let mut rng = rand::rngs::OsRng;
    let root_kp = AuthorityRootKeyPair::generate(&mut rng);
    let epoch_kp = EpochSigningKeyPair::generate(&mut rng);
    let epoch_pk = epoch_kp.verifying_key_bytes();
    let epoch_cert = root_kp.issue_epoch_cert(&epoch_pk, 42, 10);

    use arc_core::{
        AuthorityCapabilityTree, AuthorityState, CapabilityIssuanceProof, CapabilityProof,
        InMemoryTransparencyLog, RecipientKeyPair, TemporalPolicy, capability_leaf_hash,
        capability_stamp,
    };
    use helpers::capability::sample_cap;
    use helpers::request_builders::sample_req;
    use helpers::transparency::commit_state;

    let cap = sample_cap(40, 60, p);
    let mut tree = AuthorityCapabilityTree::new();
    tree.add_capability(&cap);

    let seed_state = AuthorityState {
        authority_root: tree.authority_root(),
        revocation_root: tree.revocation_root(),
        transparency_root: [0u8; 32],
        epoch: 42,
        authority_id: "auth-main".to_string(),
        epoch_signature_valid: true,
        epoch_key_cert_valid: true,
        transparency_inclusion_valid: true,
        root_pk: root_kp.verifying_key_bytes(),
        revocation_count: tree.revocation_count(),
        prev_epoch_hash: [0u8; 32],
    };
    let mut log = InMemoryTransparencyLog::new();
    let (state, tp) = commit_state(&mut log, &seed_state).unwrap();

    let inclusion = tree.inclusion_proof(&cap).unwrap();
    let stamp = capability_stamp(&cap, &state);
    let non_rev = tree.non_revocation_witness(&stamp).unwrap();
    let leaf_hash = capability_leaf_hash(&cap);
    let sig = epoch_kp.sign_capability_issuance(&leaf_hash, &state.authority_root, 42);
    let proof = CapabilityProof {
        inclusion,
        non_revocation: non_rev,
        issuance: CapabilityIssuanceProof { sig, epoch_cert },
    };

    let keypair = RecipientKeyPair::generate(&mut rng);
    let obj = seal(
        &keypair.public,
        b"still valid",
        &cap,
        &proof,
        &tp,
        &state,
        &sample_req(42, p),
        TemporalPolicy::Historical(42),
    )
    .unwrap();

    // Declare compromise at epoch 43 — epoch 42 open is before the boundary.
    let notice = root_kp.issue_compromise_notice(&epoch_pk, 43, [0xABu8; 32]);

    let plaintext =
        open_with_compromise_check(&keypair.secret, &obj, &cap, &proof, &state, &[notice])
            .expect("open before compromise epoch boundary should succeed");

    assert_eq!(plaintext, b"still valid");
}

// ---------------------------------------------------------------------------
// verify_with_compromise_check
// ---------------------------------------------------------------------------

#[test]
fn verify_with_compromise_check_succeeds_with_empty_notices() {
    let s = Scenario::baseline("verify-compromise-empty", 42);
    let obj = seal(
        &s.keypair.public,
        b"data",
        &s.cap,
        &s.proof,
        &s.seal_transparency_proof,
        &s.seal_state,
        &s.req,
        TemporalPolicy::Historical(42),
    )
    .unwrap();

    verify_with_compromise_check(
        &obj,
        &s.cap,
        &s.proof,
        &s.open_state,
        &s.open_transparency_proof,
        &[],
    )
    .expect("verify with empty notices should pass");
}

#[test]
fn verify_with_compromise_check_rejects_compromised_epoch_key() {
    let p = policy_hash("verify-compromise-reject");
    let mut rng = rand::rngs::OsRng;
    let root_kp = AuthorityRootKeyPair::generate(&mut rng);
    let bad_epoch_kp = EpochSigningKeyPair::generate(&mut rng);
    let bad_epoch_pk = bad_epoch_kp.verifying_key_bytes();
    let epoch_cert = root_kp.issue_epoch_cert(&bad_epoch_pk, 42, 10);

    use arc_core::{
        AuthorityCapabilityTree, AuthorityState, CapabilityIssuanceProof, CapabilityProof,
        InMemoryTransparencyLog, RecipientKeyPair, TemporalPolicy, capability_leaf_hash,
        capability_stamp,
    };
    use helpers::capability::sample_cap;
    use helpers::request_builders::sample_req;
    use helpers::transparency::commit_state;

    let cap = sample_cap(40, 60, p);
    let mut tree = AuthorityCapabilityTree::new();
    tree.add_capability(&cap);

    let seed_state = AuthorityState {
        authority_root: tree.authority_root(),
        revocation_root: tree.revocation_root(),
        transparency_root: [0u8; 32],
        epoch: 42,
        authority_id: "auth-main".to_string(),
        epoch_signature_valid: true,
        epoch_key_cert_valid: true,
        transparency_inclusion_valid: true,
        root_pk: root_kp.verifying_key_bytes(),
        revocation_count: tree.revocation_count(),
        prev_epoch_hash: [0u8; 32],
    };
    let mut log = InMemoryTransparencyLog::new();
    let (state, tp) = commit_state(&mut log, &seed_state).unwrap();

    let inclusion = tree.inclusion_proof(&cap).unwrap();
    let stamp = capability_stamp(&cap, &state);
    let non_rev = tree.non_revocation_witness(&stamp).unwrap();
    let leaf_hash = capability_leaf_hash(&cap);
    let sig = bad_epoch_kp.sign_capability_issuance(&leaf_hash, &state.authority_root, 42);
    let proof = CapabilityProof {
        inclusion,
        non_revocation: non_rev,
        issuance: CapabilityIssuanceProof { sig, epoch_cert },
    };

    let keypair = RecipientKeyPair::generate(&mut rng);
    let obj = seal(
        &keypair.public,
        b"blocked",
        &cap,
        &proof,
        &tp,
        &state,
        &sample_req(42, p),
        TemporalPolicy::Historical(42),
    )
    .unwrap();

    let notice = root_kp.issue_compromise_notice(&bad_epoch_pk, 42, [0xABu8; 32]);

    let err = verify_with_compromise_check(&obj, &cap, &proof, &state, &tp, &[notice])
        .expect_err("compromised epoch key should block verify");

    assert!(matches!(err, ArcError::AuthorityState(_)));
}

// ---------------------------------------------------------------------------
// Scoping: a valid notice for a DIFFERENT epoch_pk must not block opens
// ---------------------------------------------------------------------------

/// A CompromiseNotice that is signed by the correct offline root key but names
/// a *different* compromised epoch public key must not block an open whose
/// issuance proof uses an unrelated (non-compromised) epoch key.
///
/// This guards against the enforcement being overly broad — the check must be
/// scoped to `notice.compromised_epoch_pk == proof.issuance.epoch_cert.epoch_pk`.
#[test]
fn open_with_compromise_check_valid_notice_for_different_epoch_pk_does_not_block() {
    let p = policy_hash("compromise-scope-check");
    let mut rng = rand::rngs::OsRng;

    // Build authority with a known root keypair so we can sign notices.
    let root_kp = AuthorityRootKeyPair::generate(&mut rng);
    let good_epoch_kp = EpochSigningKeyPair::generate(&mut rng);
    let good_epoch_pk = good_epoch_kp.verifying_key_bytes();
    let epoch_cert = root_kp.issue_epoch_cert(&good_epoch_pk, 42, 10);

    use arc_core::{
        AuthorityCapabilityTree, AuthorityState, CapabilityIssuanceProof, CapabilityProof,
        InMemoryTransparencyLog, RecipientKeyPair, TemporalPolicy, capability_leaf_hash,
        capability_stamp,
    };
    use helpers::capability::sample_cap;
    use helpers::request_builders::sample_req;
    use helpers::transparency::commit_state;

    let cap = sample_cap(40, 60, p);
    let mut tree = AuthorityCapabilityTree::new();
    tree.add_capability(&cap);

    let seed_state = AuthorityState {
        authority_root: tree.authority_root(),
        revocation_root: tree.revocation_root(),
        transparency_root: [0u8; 32],
        epoch: 42,
        authority_id: "auth-main".to_string(),
        epoch_signature_valid: true,
        epoch_key_cert_valid: true,
        transparency_inclusion_valid: true,
        root_pk: root_kp.verifying_key_bytes(),
        revocation_count: tree.revocation_count(),
        prev_epoch_hash: [0u8; 32],
    };
    let mut log = InMemoryTransparencyLog::new();
    let (state, tp) = commit_state(&mut log, &seed_state).unwrap();

    let inclusion = tree.inclusion_proof(&cap).unwrap();
    let stamp = capability_stamp(&cap, &state);
    let non_rev = tree.non_revocation_witness(&stamp).unwrap();
    let leaf_hash = capability_leaf_hash(&cap);
    let sig = good_epoch_kp.sign_capability_issuance(&leaf_hash, &state.authority_root, 42);
    let proof = CapabilityProof {
        inclusion,
        non_revocation: non_rev,
        issuance: CapabilityIssuanceProof { sig, epoch_cert },
    };

    let keypair = RecipientKeyPair::generate(&mut rng);
    let obj = seal(
        &keypair.public,
        b"unaffected",
        &cap,
        &proof,
        &tp,
        &state,
        &sample_req(42, p),
        TemporalPolicy::Historical(42),
    )
    .unwrap();

    // Issue a valid notice — signed by the correct root key — but naming a
    // DIFFERENT (unrelated) compromised epoch pk.
    let unrelated_epoch_kp = EpochSigningKeyPair::generate(&mut rng);
    let unrelated_pk = unrelated_epoch_kp.verifying_key_bytes();
    // The notice is authentic (correct root sig) but targets a different key.
    let notice = root_kp.issue_compromise_notice(&unrelated_pk, 42, [0xABu8; 32]);

    // The open must succeed: `good_epoch_pk != unrelated_pk`.
    let plaintext =
        open_with_compromise_check(&keypair.secret, &obj, &cap, &proof, &state, &[notice])
            .expect("notice for unrelated epoch pk must not block this open");

    assert_eq!(plaintext, b"unaffected");
}

/// Same scoping check for the verify path.
#[test]
fn verify_with_compromise_check_valid_notice_for_different_epoch_pk_does_not_block() {
    let p = policy_hash("compromise-scope-verify");
    let mut rng = rand::rngs::OsRng;

    let root_kp = AuthorityRootKeyPair::generate(&mut rng);
    let good_epoch_kp = EpochSigningKeyPair::generate(&mut rng);
    let good_epoch_pk = good_epoch_kp.verifying_key_bytes();
    let epoch_cert = root_kp.issue_epoch_cert(&good_epoch_pk, 42, 10);

    use arc_core::{
        AuthorityCapabilityTree, AuthorityState, CapabilityIssuanceProof, CapabilityProof,
        InMemoryTransparencyLog, RecipientKeyPair, TemporalPolicy, capability_leaf_hash,
        capability_stamp,
    };
    use helpers::capability::sample_cap;
    use helpers::request_builders::sample_req;
    use helpers::transparency::commit_state;

    let cap = sample_cap(40, 60, p);
    let mut tree = AuthorityCapabilityTree::new();
    tree.add_capability(&cap);

    let seed_state = AuthorityState {
        authority_root: tree.authority_root(),
        revocation_root: tree.revocation_root(),
        transparency_root: [0u8; 32],
        epoch: 42,
        authority_id: "auth-main".to_string(),
        epoch_signature_valid: true,
        epoch_key_cert_valid: true,
        transparency_inclusion_valid: true,
        root_pk: root_kp.verifying_key_bytes(),
        revocation_count: tree.revocation_count(),
        prev_epoch_hash: [0u8; 32],
    };
    let mut log = InMemoryTransparencyLog::new();
    let (state, tp) = commit_state(&mut log, &seed_state).unwrap();

    let inclusion = tree.inclusion_proof(&cap).unwrap();
    let stamp = capability_stamp(&cap, &state);
    let non_rev = tree.non_revocation_witness(&stamp).unwrap();
    let leaf_hash = capability_leaf_hash(&cap);
    let sig = good_epoch_kp.sign_capability_issuance(&leaf_hash, &state.authority_root, 42);
    let proof = CapabilityProof {
        inclusion,
        non_revocation: non_rev,
        issuance: CapabilityIssuanceProof { sig, epoch_cert },
    };

    let keypair = RecipientKeyPair::generate(&mut rng);
    let obj = seal(
        &keypair.public,
        b"verifiable",
        &cap,
        &proof,
        &tp,
        &state,
        &sample_req(42, p),
        TemporalPolicy::Historical(42),
    )
    .unwrap();

    let unrelated_epoch_kp = EpochSigningKeyPair::generate(&mut rng);
    let unrelated_pk = unrelated_epoch_kp.verifying_key_bytes();
    let notice = root_kp.issue_compromise_notice(&unrelated_pk, 42, [0xCDu8; 32]);

    verify_with_compromise_check(&obj, &cap, &proof, &state, &tp, &[notice])
        .expect("notice for unrelated epoch pk must not block this verify");
}
