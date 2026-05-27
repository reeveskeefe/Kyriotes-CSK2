/// Integration tests for epoch rotation — `rotate_epoch` and
/// `rotate_epoch_and_commit` (spec §7).

mod helpers;

use arc_core::{
    AuthorityCapabilityTree,
    AuthorityState,
    BasicAuthorityVerifier,
    Capability,
    CapabilityIssuanceProof,
    CapabilityProof,
    EpochRotation,
    EpochSigningKeyPair,
    AuthorityRootKeyPair,
    InMemoryTransparencyLog,
    RecipientKeyPair,
    TemporalPolicy,
    TransparencyLog,
    capability_leaf_hash,
    capability_stamp,
    issue_capability,
    open,
    open_with_verifier,
    rotate_epoch,
    rotate_epoch_and_commit,
    rotate_epoch_full,
    seal_and_commit,
    seal_with_verifier,
    verify_epoch_cert,
    verify_with_verifier,
};
use helpers::{
    capability::sample_cap,
    request_builders::{policy_hash, sample_req},
};

// ---------------------------------------------------------------------------
// Shared setup
// ---------------------------------------------------------------------------

struct Authority {
    root_kp: AuthorityRootKeyPair,
    cap: Capability,
    tree: AuthorityCapabilityTree,
    base_state: AuthorityState,
    issuance_proof: CapabilityIssuanceProof,
}

impl Authority {
    fn new(policy_label: &str) -> Self {
        let mut rng = rand::rngs::OsRng;
        let p = policy_hash(policy_label);
        let cap = sample_cap(40, 80, p);
        let root_kp = AuthorityRootKeyPair::generate(&mut rng);
        // Seed epoch 42 just to establish the initial state
        let epoch_kp = EpochSigningKeyPair::generate(&mut rng);
        let epoch_cert = root_kp.issue_epoch_cert(&epoch_kp.verifying_key_bytes(), 42, 20);
        let mut tree = AuthorityCapabilityTree::new();
        let issuance_proof =
            issue_capability(&mut tree, &cap, &epoch_kp, &epoch_cert).expect("issue");
        let base_state = AuthorityState {
            authority_root: tree.authority_root(),
            revocation_root: tree.revocation_root(),
            transparency_root: [0u8; 32],
            epoch: 42,
            authority_id: "auth-rotation".to_string(),
            epoch_signature_valid: true,
            epoch_key_cert_valid: true,
            transparency_inclusion_valid: true,
            root_pk: root_kp.verifying_key_bytes(),
            revocation_count: tree.revocation_count(),
            prev_epoch_hash: [0u8; 32],
        };
        Self { root_kp, cap, tree, base_state, issuance_proof }
    }

    /// Issue the capability into a fresh tree under the given epoch keypair,
    /// returning the new issuance proof. The capability roots are unaffected
    /// since `issue_capability` is idempotent for caps already in the tree.
    fn reissue(&self, epoch_kp: &EpochSigningKeyPair, epoch_cert: &arc_core::EpochKeyCert) -> CapabilityIssuanceProof {
        let mut fresh_tree = AuthorityCapabilityTree::new();
        issue_capability(&mut fresh_tree, &self.cap, epoch_kp, epoch_cert)
            .expect("reissue capability")
    }

    fn build_proof(&self, cap: &arc_core::Capability, state: &AuthorityState) -> CapabilityProof {
        self.build_proof_with_issuance(cap, state, self.issuance_proof.clone())
    }

    fn build_proof_with_issuance(
        &self,
        cap: &arc_core::Capability,
        state: &AuthorityState,
        issuance: CapabilityIssuanceProof,
    ) -> CapabilityProof {
        let stamp = capability_stamp(cap, state);
        let inclusion = self.tree.inclusion_proof(cap).expect("cap in tree");
        let non_revocation =
            self.tree.non_revocation_witness(&stamp).expect("not revoked");
        CapabilityProof { inclusion, non_revocation, issuance }
    }
}

// ---------------------------------------------------------------------------
// rotate_epoch
// ---------------------------------------------------------------------------

/// The rotated state must carry the new epoch number and preserve the
/// authority root, revocation root, root_pk, and revocation count.
#[test]
fn rotate_epoch_advances_epoch_and_preserves_roots() {
    let a = Authority::new("re-preserve");

    let (_epoch_kp, _epoch_cert, new_state, _sigma_e) =
        rotate_epoch(&a.root_kp, &a.base_state, 50, 10, &[0u8; 32]);

    assert_eq!(new_state.epoch, 50, "epoch must be advanced to 50");
    assert_eq!(
        new_state.authority_root, a.base_state.authority_root,
        "authority_root must be preserved"
    );
    assert_eq!(
        new_state.revocation_root, a.base_state.revocation_root,
        "revocation_root must be preserved"
    );
    assert_eq!(
        new_state.root_pk, a.base_state.root_pk,
        "root_pk must be preserved"
    );
    assert_eq!(
        new_state.revocation_count, a.base_state.revocation_count,
        "revocation_count must be preserved"
    );
    assert_eq!(
        new_state.transparency_root,
        [0u8; 32],
        "transparency_root must be zero before commit"
    );
}

/// The epoch cert produced by `rotate_epoch` must verify under the root key.
#[test]
fn rotate_epoch_produces_valid_epoch_cert() {
    let a = Authority::new("re-cert");

    let (_epoch_kp, epoch_cert, _new_state, _sigma_e) =
        rotate_epoch(&a.root_kp, &a.base_state, 55, 10, &[0u8; 32]);

    verify_epoch_cert(&a.root_kp.verifying_key_bytes(), &epoch_cert)
        .expect("epoch cert produced by rotate_epoch must verify under root key");
    assert_eq!(epoch_cert.epoch, 55, "cert epoch must match requested new_epoch");
}

/// The epoch_pk in the cert must match the verifying key of the returned
/// `EpochSigningKeyPair`.
#[test]
fn rotate_epoch_cert_pk_matches_signing_keypair() {
    let a = Authority::new("re-pk-match");

    let (epoch_kp, epoch_cert, _new_state, _sigma_e) =
        rotate_epoch(&a.root_kp, &a.base_state, 60, 10, &[0u8; 32]);

    assert_eq!(
        epoch_cert.epoch_pk,
        epoch_kp.verifying_key_bytes(),
        "cert epoch_pk must match the returned epoch keypair's verifying key"
    );
}

/// Two successive rotations must produce distinct epoch keypairs.
#[test]
fn rotate_epoch_successive_rotations_have_distinct_keys() {
    let a = Authority::new("re-distinct");

    let (kp1, cert1, _, _) = rotate_epoch(&a.root_kp, &a.base_state, 50, 10, &[0u8; 32]);
    let (kp2, cert2, _, _) = rotate_epoch(&a.root_kp, &a.base_state, 51, 10, &[0u8; 32]);

    assert_ne!(
        kp1.verifying_key_bytes(),
        kp2.verifying_key_bytes(),
        "successive rotations must produce distinct epoch keys"
    );
    assert_ne!(
        cert1.epoch_pk, cert2.epoch_pk,
        "successive epoch certs must bind distinct keys"
    );
}

// ---------------------------------------------------------------------------
// rotate_epoch_and_commit
// ---------------------------------------------------------------------------

/// `rotate_epoch_and_commit` must fill in a real (non-zero) transparency root.
#[test]
fn rotate_epoch_and_commit_produces_transparency_root() {
    let a = Authority::new("rec-root");
    let mut log = InMemoryTransparencyLog::new();

    let (_epoch_kp, _epoch_cert, commit) =
        rotate_epoch_and_commit(&mut log, &a.root_kp, &a.base_state, 50, 10, &[0u8; 32])
            .expect("rotate_epoch_and_commit should succeed");

    assert_ne!(
        commit.state.transparency_root,
        [0u8; 32],
        "committed state must have a real transparency root"
    );
    assert_eq!(commit.state.epoch, 50, "committed state epoch must be 50");
}

/// After rotating to a new epoch and committing, it must be possible to seal
/// and then open an object using the new epoch's key and committed state.
#[test]
fn rotate_epoch_and_commit_enables_seal_open_roundtrip() {
    let p = policy_hash("rec-roundtrip");
    let cap = sample_cap(40, 80, p);
    let a = Authority::new("rec-roundtrip");
    let mut log = InMemoryTransparencyLog::new();

    // Rotate to epoch 50.
    let (epoch_kp50, epoch_cert50, commit50) =
        rotate_epoch_and_commit(&mut log, &a.root_kp, &a.base_state, 50, 10, &[0u8; 32])
            .expect("rotate to epoch 50 should succeed");

    // Re-issue the capability proof under epoch 50's key.
    let issuance50 = a.reissue(&epoch_kp50, &epoch_cert50);
    let proof50 = a.build_proof_with_issuance(&cap, &commit50.state, issuance50);
    let req50 = sample_req(50, p);
    let recipient = RecipientKeyPair::generate(&mut rand::rngs::OsRng);
    let verifier = BasicAuthorityVerifier;
    let message = b"epoch-50 payload";

    let (object, sealed_commit) = seal_and_commit(
        &mut log,
        &verifier,
        &recipient.public,
        message,
        &cap,
        &proof50,
        &commit50.state,
        &req50,
        TemporalPolicy::Historical(50),
    )
    .expect("seal_and_commit at epoch 50 should succeed");

    let opened = open(
        &recipient.secret,
        &object,
        &cap,
        &proof50,
        &sealed_commit.state,
    )
    .expect("open at epoch 50 should succeed");

    assert_eq!(opened, message, "decrypted message must match original");
}

/// Rotating to epoch N and then to epoch N+1 (chained rotation) must produce
/// a committed state at N+1 that seals/opens correctly.
#[test]
fn rotate_epoch_chained_rotation_seal_open() {
    let p = policy_hash("rec-chain");
    let cap = sample_cap(40, 80, p);
    let mut a = Authority::new("rec-chain");
    let mut log = InMemoryTransparencyLog::new();

    // First rotation: epoch 42 → 50
    let (epoch_kp50, epoch_cert50, commit50) =
        rotate_epoch_and_commit(&mut log, &a.root_kp, &a.base_state, 50, 10, &[0u8; 32])
            .expect("rotate to 50");

    // Second rotation: epoch 50 → 60
    let (epoch_kp60, epoch_cert60, commit60) =
        rotate_epoch_and_commit(&mut log, &a.root_kp, &commit50.state, 60, 10, &[0u8; 32])
            .expect("rotate to 60");

    assert_eq!(commit60.state.epoch, 60);
    assert_ne!(commit60.state.transparency_root, [0u8; 32]);

    // Seal at epoch 60 with the epoch-60 key.
    let issuance60 = a.reissue(&epoch_kp60, &epoch_cert60);
    let proof60 = a.build_proof_with_issuance(&cap, &commit60.state, issuance60);
    let req60 = sample_req(60, p);
    let recipient = RecipientKeyPair::generate(&mut rand::rngs::OsRng);
    let verifier = BasicAuthorityVerifier;
    let message = b"chained epoch-60 payload";

    let (object, sealed_commit) = seal_and_commit(
        &mut log,
        &verifier,
        &recipient.public,
        message,
        &cap,
        &proof60,
        &commit60.state,
        &req60,
        TemporalPolicy::Historical(60),
    )
    .expect("seal_and_commit at epoch 60");

    let opened = open(
        &recipient.secret,
        &object,
        &cap,
        &proof60,
        &sealed_commit.state,
    )
    .expect("open at epoch 60");

    assert_eq!(opened, message);
}

/// `rotate_epoch_and_commit` must fail if trying to commit a different state
/// for the same `(authority_id, epoch)` that is already in the log.
#[test]
fn rotate_epoch_and_commit_rejects_conflicting_state() {
    let a = Authority::new("rec-conflict");
    let mut log = InMemoryTransparencyLog::new();

    // First rotation to epoch 50 succeeds.
    rotate_epoch_and_commit(&mut log, &a.root_kp, &a.base_state, 50, 10, &[0u8; 32])
        .expect("first rotate to epoch 50 should succeed");

    // Manually commit a *different* state for the same (authority_id, epoch=50).
    // We do this by building a state that differs in revocation_count.
    let mut conflicting = a.base_state.clone();
    conflicting.epoch = 50;
    conflicting.revocation_count = 99; // different from 0

    let err = log.commit_state(&conflicting)
        .expect_err("committing conflicting state for same epoch must fail");
    // The exact error message contains "already contains"
    match err {
        arc_core::ArcError::AuthorityState(msg) => {
            assert!(
                msg.contains("already"),
                "error must mention the conflict: {msg}"
            );
        }
        other => panic!("expected AuthorityState error, got: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// rotate_epoch_full — ergonomic API (spec §7)
// ---------------------------------------------------------------------------

fn base_setup_full(authority_id: &str, epoch: u64) -> (
    AuthorityRootKeyPair,
    AuthorityState,
    InMemoryTransparencyLog,
) {
    use helpers::transparency::commit_state;
    let mut rng = rand::rngs::OsRng;
    let root_kp = AuthorityRootKeyPair::generate(&mut rng);
    let seed = AuthorityState {
        authority_root: [0u8; 32],
        revocation_root: [0u8; 32],
        transparency_root: [0u8; 32],
        epoch,
        authority_id: authority_id.to_string(),
        epoch_signature_valid: true,
        epoch_key_cert_valid: true,
        transparency_inclusion_valid: true,
        root_pk: root_kp.verifying_key_bytes(),
        revocation_count: 0,
        prev_epoch_hash: [0u8; 32],
    };
    let mut log = InMemoryTransparencyLog::new();
    let (state, _) = commit_state(&mut log, &seed).unwrap();
    (root_kp, state, log)
}

#[test]
fn rotate_epoch_full_returns_correct_epoch_number() {
    let (root_kp, base_state, mut log) = base_setup_full("auth-full-basic", 1);
    let rot = rotate_epoch_full(&mut log, &root_kp, &base_state, 2, 100, &[0u8; 32])
        .expect("rotation should succeed");
    assert_eq!(rot.state.epoch, 2);
}

#[test]
fn rotate_epoch_full_epoch_pk_matches_keypair() {
    let (root_kp, base_state, mut log) = base_setup_full("auth-full-pk", 1);
    let rot = rotate_epoch_full(&mut log, &root_kp, &base_state, 2, 100, &[0u8; 32])
        .expect("rotation");
    assert_eq!(rot.epoch_pk, rot.epoch_kp.verifying_key_bytes());
}

#[test]
fn rotate_epoch_full_sigma_e_is_nonzero() {
    let (root_kp, base_state, mut log) = base_setup_full("auth-full-sigma", 1);
    let rot = rotate_epoch_full(&mut log, &root_kp, &base_state, 2, 100, &[0u8; 32])
        .expect("rotation");
    assert_ne!(rot.sigma_e, [0u8; 64], "sigma_e must be a real signature");
}

#[test]
fn rotate_epoch_full_chain_hash_is_nonzero() {
    let (root_kp, base_state, mut log) = base_setup_full("auth-full-chain", 1);
    let rot = rotate_epoch_full(&mut log, &root_kp, &base_state, 2, 100, &[0u8; 32])
        .expect("rotation");
    assert_ne!(rot.chain_hash, [0u8; 32], "chain_hash must be set");
}

#[test]
fn rotate_epoch_full_into_verifier_seal_open_roundtrip() {
    let p = policy_hash("full-seal-open");
    let mut rng = rand::rngs::OsRng;
    let root_kp = AuthorityRootKeyPair::generate(&mut rng);

    let cap = sample_cap(1, 10, p);
    let mut tree = AuthorityCapabilityTree::new();
    tree.add_capability(&cap);

    let seed = AuthorityState {
        authority_root: tree.authority_root(),
        revocation_root: tree.revocation_root(),
        transparency_root: [0u8; 32],
        epoch: 1,
        authority_id: "auth-full-roundtrip".to_string(),
        epoch_signature_valid: true,
        epoch_key_cert_valid: true,
        transparency_inclusion_valid: true,
        root_pk: root_kp.verifying_key_bytes(),
        revocation_count: tree.revocation_count(),
        prev_epoch_hash: [0u8; 32],
    };
    let mut log = InMemoryTransparencyLog::new();
    let (base_state, _) = { use helpers::transparency::commit_state; commit_state(&mut log, &seed).unwrap() };

    let rot = rotate_epoch_full(&mut log, &root_kp, &base_state, 2, 100, &[0u8; 32])
        .expect("rotation");
    let verifier = rot.into_verifier();

    let inclusion = tree.inclusion_proof(&cap).unwrap();
    let stamp = capability_stamp(&cap, &rot.state);
    let non_rev = tree.non_revocation_witness(&stamp).unwrap();
    let leaf = capability_leaf_hash(&cap);
    let sig = rot.epoch_kp.sign_capability_issuance(&leaf, &rot.state.authority_root, 2);
    let proof = CapabilityProof {
        inclusion,
        non_revocation: non_rev,
        issuance: CapabilityIssuanceProof { sig, epoch_cert: rot.epoch_cert.clone() },
    };

    let keypair = RecipientKeyPair::generate(&mut rng);
    let req = sample_req(2, p);

    let obj = seal_with_verifier(
        &verifier, &keypair.public, b"ergonomic api",
        &cap, &proof, &rot.transparency_proof, &rot.state, &req,
        TemporalPolicy::Historical(2),
    ).expect("seal");

    let pt = open_with_verifier(&verifier, &keypair.secret, &obj, &cap, &proof, &rot.state)
        .expect("open");

    assert_eq!(pt, b"ergonomic api");
}

#[test]
fn rotate_epoch_full_into_verifier_verify_path() {
    let p = policy_hash("full-verify-path");
    let mut rng = rand::rngs::OsRng;
    let root_kp = AuthorityRootKeyPair::generate(&mut rng);

    let cap = sample_cap(1, 10, p);
    let mut tree = AuthorityCapabilityTree::new();
    tree.add_capability(&cap);

    let seed = AuthorityState {
        authority_root: tree.authority_root(),
        revocation_root: tree.revocation_root(),
        transparency_root: [0u8; 32],
        epoch: 1,
        authority_id: "auth-full-verify".to_string(),
        epoch_signature_valid: true,
        epoch_key_cert_valid: true,
        transparency_inclusion_valid: true,
        root_pk: root_kp.verifying_key_bytes(),
        revocation_count: tree.revocation_count(),
        prev_epoch_hash: [0u8; 32],
    };
    let mut log = InMemoryTransparencyLog::new();
    let (base_state, _) = { use helpers::transparency::commit_state; commit_state(&mut log, &seed).unwrap() };

    let rot = rotate_epoch_full(&mut log, &root_kp, &base_state, 2, 100, &[0u8; 32])
        .expect("rotation");
    let verifier = rot.into_verifier();

    let inclusion = tree.inclusion_proof(&cap).unwrap();
    let stamp = capability_stamp(&cap, &rot.state);
    let non_rev = tree.non_revocation_witness(&stamp).unwrap();
    let leaf = capability_leaf_hash(&cap);
    let sig = rot.epoch_kp.sign_capability_issuance(&leaf, &rot.state.authority_root, 2);
    let proof = CapabilityProof {
        inclusion,
        non_revocation: non_rev,
        issuance: CapabilityIssuanceProof { sig, epoch_cert: rot.epoch_cert.clone() },
    };

    let keypair = RecipientKeyPair::generate(&mut rng);
    let req = sample_req(2, p);

    let obj = seal_with_verifier(
        &verifier, &keypair.public, b"verify me",
        &cap, &proof, &rot.transparency_proof, &rot.state, &req,
        TemporalPolicy::Historical(2),
    ).expect("seal");

    verify_with_verifier(&verifier, &obj, &cap, &proof, &rot.state, &rot.transparency_proof)
        .expect("verify_with_verifier via into_verifier must succeed");
}

#[test]
fn chained_rotations_chain_hash_differs() {
    let (root_kp, base_state, mut log) = base_setup_full("auth-chained", 1);

    let rot1 = rotate_epoch_full(&mut log, &root_kp, &base_state, 2, 100, &[0u8; 32])
        .expect("first rotation");
    let rot2 = rotate_epoch_full(&mut log, &root_kp, &rot1.state, 3, 100, &rot1.chain_hash)
        .expect("second rotation");

    assert_eq!(rot1.state.epoch, 2);
    assert_eq!(rot2.state.epoch, 3);
    assert_ne!(rot1.chain_hash, rot2.chain_hash, "chain hashes must differ across epochs");
}
