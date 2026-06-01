/// Tests for `parent_stamp` and `version` fields in `Capability` (spec §5, §25a).
///
/// Both fields are required in `capability_leaf_hash`; `parent_stamp` binds
/// delegated capabilities to their parent; `version` identifies the capability
/// format.  For directly-issued capabilities, `parent_stamp` is `[0u8; 32]`
/// and `version` is `1`.
mod helpers;

use helpers::{capability::sample_cap, request_builders::policy_hash, scenario::Scenario};
use kyriotes_csk2::{
    StubAuthorityVerifier, Capability, InMemoryTransparencyLog, capability_leaf_hash, open,
    seal_and_commit,
};

// ---------------------------------------------------------------------------
// Leaf-hash sensitivity tests
// ---------------------------------------------------------------------------

/// Two capabilities that differ only in `parent_stamp` must produce different
/// `capability_leaf_hash` values (spec §25a).
#[test]
fn parent_stamp_changes_leaf_hash() {
    let p = policy_hash("ps-leaf-hash");
    let cap_a = Capability {
        parent_stamp: [0u8; 32],
        ..sample_cap(40, 60, p)
    };
    let cap_b = Capability {
        parent_stamp: [1u8; 32],
        ..sample_cap(40, 60, p)
    };
    assert_ne!(
        capability_leaf_hash(&cap_a),
        capability_leaf_hash(&cap_b),
        "different parent_stamp must produce different leaf hash"
    );
}

/// Two capabilities that differ only in `version` must produce different
/// `capability_leaf_hash` values.
#[test]
fn version_changes_leaf_hash() {
    let p = policy_hash("ps-version-hash");
    let cap_v1 = Capability {
        version: 1,
        ..sample_cap(40, 60, p)
    };
    let cap_v2 = Capability {
        version: 2,
        ..sample_cap(40, 60, p)
    };
    assert_ne!(
        capability_leaf_hash(&cap_v1),
        capability_leaf_hash(&cap_v2),
        "different version must produce different leaf hash"
    );
}

// ---------------------------------------------------------------------------
// End-to-end round-trip with default fields
// ---------------------------------------------------------------------------

/// A capability with `version: 1` and `parent_stamp: [0u8; 32]` must seal and
/// open successfully end-to-end — the default values must not break any
/// cryptographic invariant.
#[test]
fn default_values_roundtrip_seal_open() {
    let s = Scenario::baseline("ps-roundtrip", 42).with_message(b"roundtrip payload");

    // Verify the default cap has the expected fields.
    assert_eq!(s.cap.version, 1, "sample_cap must default to version 1");
    assert_eq!(
        s.cap.parent_stamp, [0u8; 32],
        "sample_cap must default to zero parent_stamp"
    );

    let mut log = InMemoryTransparencyLog::new();
    let verifier = StubAuthorityVerifier;

    let (object, commit) = seal_and_commit(
        &mut log,
        &verifier,
        &s.keypair.public,
        &s.message,
        &s.cap,
        &s.proof,
        &s.seal_state,
        &s.req,
        s.temporal_policy.clone(),
    )
    .expect("seal_and_commit should succeed");

    let proof_at_commit = s.build_proof_for_state(&commit.state);
    let plaintext = open(
        &s.keypair.secret,
        &object,
        &s.cap,
        &proof_at_commit,
        &commit.state,
    )
    .expect("open should succeed");

    assert_eq!(plaintext, s.message);
}
