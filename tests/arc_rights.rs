/// Integration tests for capability rights satisfaction (spec §9 ValidCap check 4).
///
/// ARC requires cap.rights ⊇ req.required_rights for both seal and open.
/// This file tests the boundary between acceptance and rejection across
/// different rights combinations.
mod helpers;

use arc_core::{
    ArcError, AuthorityState, Capability, InMemoryTransparencyLog,
    OpenRequest, RecipientKeyPair, Rights, TemporalPolicy,
    open, seal,
};
use helpers::capability::TestAuthority;
use helpers::request_builders::{DEFAULT_OBJECT_ID, policy_hash};
use helpers::transparency::commit_state;

const EPOCH: u64 = 42;

fn make_cap(rights: Rights, p_hash: [u8; 32]) -> Capability {
    Capability {
        subject: "test-subject".to_string(),
        object_id: DEFAULT_OBJECT_ID.to_string(),
        rights,
        policy_hash: p_hash,
        epoch_start: 40,
        epoch_end: 60,
        delegation_depth: 0,
        nonce: [0xABu8; 16],
    }
}

fn make_req(rights: Rights, p_hash: [u8; 32]) -> OpenRequest {
    OpenRequest {
        object_id: DEFAULT_OBJECT_ID.to_string(),
        required_rights: rights,
        policy_hash: p_hash,
        epoch: EPOCH,
    }
}

/// Build a committed AuthorityState, transparency proof, and capability proof
/// for the given cap, using a freshly generated TestAuthority at EPOCH.
fn setup(
    cap: &Capability,
) -> (TestAuthority, AuthorityState, arc_core::TransparencyProof, arc_core::CapabilityProof) {
    let authority = TestAuthority::new_for_cap(cap, EPOCH);
    let mut log = InMemoryTransparencyLog::new();
    let seed = AuthorityState {
        authority_root: authority.authority_root(),
        revocation_root: authority.revocation_root(),
        transparency_root: [0u8; 32],
        epoch: EPOCH,
        authority_id: "auth-rights".to_string(),
        epoch_signature_valid: true,
        epoch_key_cert_valid: true,
        transparency_inclusion_valid: true,
        root_pk: authority.root_pk(),
        revocation_count: 0,
    };
    let (state, tp) = commit_state(&mut log, &seed).expect("commit should succeed");
    let proof = authority.build_proof_for_state(cap, &state);
    (authority, state, tp, proof)
}

// ---------------------------------------------------------------------------
// Acceptance cases
// ---------------------------------------------------------------------------

/// Cap holds READ|WRITE|DECRYPT (strict superset); req needs only READ.
/// All ValidCap checks pass; seal and open succeed.
#[test]
fn rights_superset_satisfies_requirement() {
    let p = policy_hash("rights-superset");
    let cap = make_cap(Rights::READ.union(Rights::WRITE).union(Rights::DECRYPT), p);
    let req = make_req(Rights::READ, p);

    let (_, state, tp, proof) = setup(&cap);
    let kp = RecipientKeyPair::generate(&mut rand::rngs::OsRng);

    let obj = seal(&kp.public, b"superset-test", &cap, &proof, &tp, &state, &req,
        TemporalPolicy::Historical(EPOCH))
        .expect("seal with superset rights should succeed");

    let plaintext = open(&kp.secret, &obj, &cap, &proof, &state)
        .expect("open with superset rights should succeed");
    assert_eq!(plaintext, b"superset-test");
}

/// Cap holds exactly READ; req also needs READ (exact match).
#[test]
fn rights_exact_match_satisfies_requirement() {
    let p = policy_hash("rights-exact");
    let cap = make_cap(Rights::READ, p);
    let req = make_req(Rights::READ, p);

    let (_, state, tp, proof) = setup(&cap);
    let kp = RecipientKeyPair::generate(&mut rand::rngs::OsRng);

    let obj = seal(&kp.public, b"exact-match", &cap, &proof, &tp, &state, &req,
        TemporalPolicy::Historical(EPOCH))
        .expect("seal with exact rights match should succeed");

    let plaintext = open(&kp.secret, &obj, &cap, &proof, &state)
        .expect("open with exact rights match should succeed");
    assert_eq!(plaintext, b"exact-match");
}

/// Cap holds READ|WRITE; req needs READ|WRITE (both required, both present).
#[test]
fn rights_multi_required_all_present_satisfies_requirement() {
    let p = policy_hash("rights-multi-all");
    let cap = make_cap(Rights::READ.union(Rights::WRITE), p);
    let req = make_req(Rights::READ.union(Rights::WRITE), p);

    let (_, state, tp, proof) = setup(&cap);
    let kp = RecipientKeyPair::generate(&mut rand::rngs::OsRng);

    let obj = seal(&kp.public, b"multi-rights", &cap, &proof, &tp, &state, &req,
        TemporalPolicy::Historical(EPOCH))
        .expect("seal with all required rights should succeed");

    let plaintext = open(&kp.secret, &obj, &cap, &proof, &state)
        .expect("open with all required rights should succeed");
    assert_eq!(plaintext, b"multi-rights");
}

// ---------------------------------------------------------------------------
// Rejection cases
// ---------------------------------------------------------------------------

/// Cap holds only READ; req requires WRITE.  Seal must fail at validate_capability.
#[test]
fn seal_rejects_when_cap_rights_insufficient() {
    let p = policy_hash("rights-insuff");
    let cap = make_cap(Rights::READ, p);
    let req = make_req(Rights::WRITE, p); // WRITE not in cap

    let (_, state, tp, proof) = setup(&cap);
    let kp = RecipientKeyPair::generate(&mut rand::rngs::OsRng);

    let err = seal(&kp.public, b"secret", &cap, &proof, &tp, &state, &req,
        TemporalPolicy::Historical(EPOCH))
        .expect_err("seal with insufficient rights must be rejected");

    assert!(
        matches!(err, ArcError::InvalidCapability("insufficient rights")),
        "expected InvalidCapability(\"insufficient rights\"), got {err:?}"
    );
}

/// Cap holds READ|DECRYPT; req requires READ|WRITE.  WRITE is missing.
#[test]
fn seal_rejects_when_one_of_multiple_required_rights_is_absent() {
    let p = policy_hash("rights-partial");
    let cap = make_cap(Rights::READ.union(Rights::DECRYPT), p);
    let req = make_req(Rights::READ.union(Rights::WRITE), p); // WRITE missing from cap

    let (_, state, tp, proof) = setup(&cap);
    let kp = RecipientKeyPair::generate(&mut rand::rngs::OsRng);

    let err = seal(&kp.public, b"secret", &cap, &proof, &tp, &state, &req,
        TemporalPolicy::Historical(EPOCH))
        .expect_err("partial rights must be rejected");

    assert!(
        matches!(err, ArcError::InvalidCapability("insufficient rights")),
        "expected InvalidCapability(\"insufficient rights\"), got {err:?}"
    );
}
