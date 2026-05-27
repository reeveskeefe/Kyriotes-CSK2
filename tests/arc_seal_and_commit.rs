/// Integration tests for `seal_and_commit` — seals a message *and* commits
/// the authority state to the transparency log in a single step.

mod helpers;

use arc_core::{
    AuthorityCapabilityTree,
    AuthorityState,
    BasicAuthorityVerifier,
    CapabilityIssuanceProof,
    CapabilityProof,
    EpochKeyCert,
    EpochSigningKeyPair,
    AuthorityRootKeyPair,
    InMemoryTransparencyLog,
    RecipientKeyPair,
    Rights,
    TemporalPolicy,
    open,
    seal_and_commit,
    issue_capability,
    capability_stamp,
};
use helpers::{
    capability::sample_cap,
    request_builders::{policy_hash, sample_req, DEFAULT_OBJECT_ID},
};

// ---------------------------------------------------------------------------
// Shared setup helpers
// ---------------------------------------------------------------------------

struct Setup {
    root_kp: AuthorityRootKeyPair,
    epoch_kp: EpochSigningKeyPair,
    epoch_cert: EpochKeyCert,
    tree: AuthorityCapabilityTree,
    issuance_proof: CapabilityIssuanceProof,
    log: InMemoryTransparencyLog,
    recipient: RecipientKeyPair,
}

impl Setup {
    fn new(cap_epoch_start: u64, cap_epoch_end: u64, cert_epoch: u64, policy_label: &str) -> Self {
        let p = policy_hash(policy_label);
        let cap = sample_cap(cap_epoch_start, cap_epoch_end, p);
        let mut rng = rand::rngs::OsRng;
        let root_kp = AuthorityRootKeyPair::generate(&mut rng);
        let epoch_kp = EpochSigningKeyPair::generate(&mut rng);
        let epoch_cert = root_kp.issue_epoch_cert(&epoch_kp.verifying_key_bytes(), cert_epoch, 10);
        let mut tree = AuthorityCapabilityTree::new();
        let issuance_proof = issue_capability(&mut tree, &cap, &epoch_kp, &epoch_cert).expect("issue_capability should succeed");
        Self {
            root_kp,
            epoch_kp,
            epoch_cert,
            tree,
            issuance_proof,
            log: InMemoryTransparencyLog::new(),
            recipient: RecipientKeyPair::generate(&mut rng),
        }
    }

    fn build_proof(&self, cap: &arc_core::Capability, state: &AuthorityState) -> CapabilityProof {
        let stamp = capability_stamp(cap, state);
        let inclusion = self.tree.inclusion_proof(cap).expect("cap must be in tree");
        let non_revocation = self.tree.non_revocation_witness(&stamp).expect("cap must not be revoked");
        CapabilityProof { inclusion, non_revocation, issuance: self.issuance_proof.clone() }
    }

    fn uncommitted_state(&self, epoch: u64) -> AuthorityState {
        AuthorityState {
            authority_root: self.tree.authority_root(),
            revocation_root: self.tree.revocation_root(),
            transparency_root: [0u8; 32],
            epoch,
            authority_id: "auth-main".to_string(),
            epoch_signature_valid: true,
            epoch_key_cert_valid: true,
            transparency_inclusion_valid: true,
            root_pk: self.root_kp.verifying_key_bytes(),
            revocation_count: self.tree.revocation_count(),
            prev_epoch_hash: [0u8; 32],
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Happy path: `seal_and_commit` returns an `ArcObject` and a
/// `TransparencyStateCommit` with a real (non-zero) transparency root.
#[test]
fn seal_and_commit_returns_valid_object_and_commit() {
    let p = policy_hash("sac-basic");
    let cap = sample_cap(40, 60, p);
    let mut s = Setup::new(40, 60, 42, "sac-basic");
    let state = s.uncommitted_state(42);
    let req = sample_req(42, p);
    let verifier = BasicAuthorityVerifier;
    let proof = s.build_proof(&cap, &state);

    let (object, commit) = seal_and_commit(
        &mut s.log,
        &verifier,
        &s.recipient.public,
        b"hello ARC",
        &cap,
        &proof,
        &state,
        &req,
        TemporalPolicy::Historical(42),
    )
    .expect("seal_and_commit should succeed");

    // Committed state must have a real transparency root.
    assert_ne!(commit.state.transparency_root, [0u8; 32], "transparency root must be set after commit");
    // Object must have exactly one wrapper.
    assert_eq!(object.wrappers.len(), 1, "sealed object must have one wrapper");
    // Wrapper epoch must match the state epoch.
    assert_eq!(object.wrappers[0].epoch, 42);
}

/// The wrapper baked into the `ArcObject` must contain the committed
/// `TransparencyProof` — not the zero-root that was in the input state.
#[test]
fn seal_and_commit_wrapper_bakes_in_committed_proof() {
    let p = policy_hash("sac-proof");
    let cap = sample_cap(40, 60, p);
    let mut s = Setup::new(40, 60, 42, "sac-proof");
    let state = s.uncommitted_state(42);
    let req = sample_req(42, p);
    let verifier = BasicAuthorityVerifier;
    let proof = s.build_proof(&cap, &state);

    let (object, commit) = seal_and_commit(
        &mut s.log,
        &verifier,
        &s.recipient.public,
        b"secret payload",
        &cap,
        &proof,
        &state,
        &req,
        TemporalPolicy::Historical(42),
    )
    .expect("seal_and_commit should succeed");

    let wrapper = &object.wrappers[0];
    // The wrapper's transparency proof leaf_hash must match the committed one.
    assert_eq!(
        wrapper.transparency_proof.leaf_hash,
        commit.proof.leaf_hash,
        "wrapper must carry the committed transparency proof"
    );
}

/// The object returned by `seal_and_commit` must be immediately openable
/// using the committed state and proof from the same call.
#[test]
fn seal_and_commit_object_is_immediately_openable() {
    let p = policy_hash("sac-open");
    let cap = sample_cap(40, 60, p);
    let mut s = Setup::new(40, 60, 42, "sac-open");
    let state = s.uncommitted_state(42);
    let req = sample_req(42, p);
    let verifier = BasicAuthorityVerifier;
    let proof = s.build_proof(&cap, &state);
    let message = b"open me right away";

    let (object, commit) = seal_and_commit(
        &mut s.log,
        &verifier,
        &s.recipient.public,
        message,
        &cap,
        &proof,
        &state,
        &req,
        TemporalPolicy::Historical(42),
    )
    .expect("seal_and_commit should succeed");

    let opened = open(
        &s.recipient.secret,
        &object,
        &cap,
        &proof,
        &commit.state,
    )
    .expect("open should succeed with committed state");

    assert_eq!(opened, message, "decrypted message must match original");
}

/// `seal_and_commit` is idempotent for the same state: committing the same
/// state twice (two separate calls) succeeds on both calls because
/// `InMemoryTransparencyLog` is idempotent for identical state.
#[test]
fn seal_and_commit_idempotent_for_same_state() {
    let p = policy_hash("sac-idempotent");
    let cap = sample_cap(40, 60, p);
    let mut s = Setup::new(40, 60, 42, "sac-idempotent");
    let state = s.uncommitted_state(42);
    let req = sample_req(42, p);
    let verifier = BasicAuthorityVerifier;

    let proof = s.build_proof(&cap, &state);

    // First call
    let (_, commit1) = seal_and_commit(
        &mut s.log,
        &verifier,
        &s.recipient.public,
        b"first",
        &cap,
        &proof,
        &state,
        &req,
        TemporalPolicy::Historical(42),
    )
    .expect("first seal_and_commit should succeed");

    // Second call with identical state — log is idempotent
    let proof2 = s.build_proof(&cap, &state);
    let (_, commit2) = seal_and_commit(
        &mut s.log,
        &verifier,
        &s.recipient.public,
        b"second",
        &cap,
        &proof2,
        &state,
        &req,
        TemporalPolicy::Historical(42),
    )
    .expect("second seal_and_commit with same state should succeed");

    // Both commits must produce the same transparency root.
    assert_eq!(
        commit1.state.transparency_root,
        commit2.state.transparency_root,
        "idempotent commits must produce the same transparency root"
    );
}

/// `seal_and_commit` must propagate capability validation errors.
/// Requesting WRITE rights against a READ-only cap must fail.
#[test]
fn seal_and_commit_rejects_insufficient_rights() {
    use arc_core::{ArcError, OpenRequest};

    let p = policy_hash("sac-rights");
    let cap = sample_cap(40, 60, p); // sample_cap produces a READ cap
    let mut s = Setup::new(40, 60, 42, "sac-rights");
    let state = s.uncommitted_state(42);

    // Request WRITE — not in cap's rights.
    let req = OpenRequest {
        object_id: DEFAULT_OBJECT_ID.to_string(),
        required_rights: Rights::WRITE,
        policy_hash: p,
        epoch: 42,
    };

    let verifier = BasicAuthorityVerifier;
    let proof = s.build_proof(&cap, &state);

    let err = seal_and_commit(
        &mut s.log,
        &verifier,
        &s.recipient.public,
        b"payload",
        &cap,
        &proof,
        &state,
        &req,
        TemporalPolicy::Historical(42),
    )
    .expect_err("seal_and_commit must reject insufficient rights");

    assert!(matches!(err, ArcError::InvalidCapability(_)));
}
