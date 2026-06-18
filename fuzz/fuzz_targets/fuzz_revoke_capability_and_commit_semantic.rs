#![no_main]

use kyriotes_csk2::{
    capability_stamp, hash_policy, issue_capability_and_commit,
    open_with_verifier, revoke_capability_and_commit, seal_with_verifier,
    verify_with_verifier, AuthorityCapabilityTree, AuthorityRootKeyPair, AuthorityState,
    Capability, CapabilityIssuanceProof, CapabilityProof, InMemoryTransparencyLog, OpenRequest,
    RecipientKeyPair, Rights, StubAuthorityVerifier, TemporalPolicy, TransparencyLog,
};
use libfuzzer_sys::fuzz_target;
use rand::{rngs::StdRng, SeedableRng};

const VALIDITY_WINDOW: u64 = 256;

fn seed32(data: &[u8], domain: u8) -> [u8; 32] {
    kyriotes_csk2_fuzz::deterministic_seed32(data, domain)
}

fn base_capability(data: &[u8], policy_hash: [u8; 32]) -> Capability {
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&seed32(data.get(8..).unwrap_or_default(), 0x71)[..16]);
    Capability {
        version: 1,
        subject: "revocation-subject".to_string(),
        object_id: format!(
            "revocation-object-{:016x}",
            kyriotes_csk2_fuzz::bytes_to_u64(data)
        ),
        rights: Rights::READ.union(Rights::DECRYPT),
        policy_hash,
        epoch_start: 1,
        epoch_end: 4096,
        delegation_depth: 0,
        parent_stamp: [0u8; 32],
        nonce,
    }
}

fn authority_state(
    tree: &AuthorityCapabilityTree,
    root_pk: [u8; 32],
    authority_id: String,
    epoch: u64,
) -> AuthorityState {
    AuthorityState {
        authority_root: tree.authority_root(),
        revocation_root: tree.revocation_root(),
        transparency_root: [0u8; 32],
        epoch,
        authority_id,
        root_pk,
        revocation_count: tree.revocation_count(),
        prev_epoch_hash: [0u8; 32],
    }
}

fn build_capability_proof(
    tree: &AuthorityCapabilityTree,
    cap: &Capability,
    issuance: CapabilityIssuanceProof,
    state: &AuthorityState,
) -> Option<CapabilityProof> {
    Some(CapabilityProof {
        inclusion: tree.inclusion_proof(cap)?,
        non_revocation: tree.non_revocation_witness(&capability_stamp(cap, state)).ok()?,
        issuance,
    })
}

fn fuzz_revoke_capability_and_commit_semantic(data: &[u8]) {
    let data = kyriotes_csk2_fuzz::bounded(data);
    let mut rng = StdRng::from_seed(seed32(data, 0x17));

    let root_kp = AuthorityRootKeyPair::from_seed(seed32(data.get(1..).unwrap_or_default(), 0x27));
    let epoch_kp = kyriotes_csk2::EpochSigningKeyPair::from_seed(seed32(
        data.get(3..).unwrap_or_default(),
        0x37,
    ));
    let policy_hash = hash_policy(&format!(
        "revocation-policy-{:016x}",
        kyriotes_csk2_fuzz::bytes_to_u64(data.get(5..).unwrap_or_default())
    ));

    let mut tree = AuthorityCapabilityTree::new();
    let cap = base_capability(data, policy_hash);
    tree.add_capability(&cap);

    let base_epoch = (kyriotes_csk2_fuzz::bytes_to_u64(data.get(13..).unwrap_or_default()) % 32)
        .saturating_add(1);
    let revoke_gap = (data.get(21).copied().unwrap_or(0) as u64 % 6).saturating_add(1);
    let revoke_epoch = base_epoch.saturating_add(revoke_gap);
    let authority_id = format!(
        "revocation-fuzz-auth-{}",
        data.first().copied().unwrap_or(0)
    );

    let base_state = authority_state(
        &tree,
        root_kp.verifying_key_bytes(),
        authority_id,
        base_epoch,
    );

    let mut log = InMemoryTransparencyLog::new();
    let base_epoch_cert = root_kp.issue_epoch_cert(
        &epoch_kp.verifying_key_bytes(),
        base_epoch,
        VALIDITY_WINDOW,
    );
    let Some((issuance, base_commit)) = issue_capability_and_commit(
        &mut log,
        &mut tree,
        &cap,
        &epoch_kp,
        &base_epoch_cert,
        &base_state,
    )
    .ok() else {
        return;
    };

    let base_proof = match build_capability_proof(&tree, &cap, issuance, &base_commit.state) {
        Some(value) => value,
        None => return,
    };

    let recipient = RecipientKeyPair::generate(&mut rng);
    let verifier = StubAuthorityVerifier;
    let open_request = OpenRequest {
        object_id: cap.object_id.clone(),
        required_rights: Rights::READ,
        policy_hash,
        epoch: base_commit.state.epoch,
    };

    let object = match seal_with_verifier(
        &verifier,
        &recipient.public,
        data,
        &cap,
        &base_proof,
        &base_commit.proof,
        &base_commit.state,
        &open_request,
        TemporalPolicy::Current,
    ) {
        Ok(value) => value,
        Err(_) => return,
    };

    let revoked_commit = match revoke_capability_and_commit(
        &mut log,
        &mut tree,
        &cap,
        &base_commit.state,
        revoke_epoch,
    ) {
        Ok(value) => value,
        Err(_) => return,
    };

    assert_eq!(revoked_commit.state.epoch, revoke_epoch);
    assert_eq!(revoked_commit.state.authority_root, base_commit.state.authority_root);
    assert_ne!(revoked_commit.state.revocation_root, base_commit.state.revocation_root);
    assert_ne!(revoked_commit.state.transparency_root, [0u8; 32]);

    let revoked_stamp = capability_stamp(&cap, &revoked_commit.state);
    assert!(tree.is_revoked(&revoked_stamp));
    assert!(tree.non_revocation_witness(&revoked_stamp).is_err());

    let roundtrip_proof = log
        .proof_for_state(&revoked_commit.state)
        .expect("revoked state must be in transparency log");
    assert_eq!(roundtrip_proof.leaf_hash, revoked_commit.proof.leaf_hash);

    assert!(
        verify_with_verifier(
            &verifier,
            &object,
            &cap,
            &base_proof,
            &revoked_commit.state,
            &revoked_commit.proof,
        )
        .is_err(),
        "revoked state must not verify the pre-revocation object"
    );
    assert!(
        open_with_verifier(
            &verifier,
            &recipient.secret,
            &object,
            &cap,
            &base_proof,
            &revoked_commit.state,
        )
        .is_err(),
        "revoked state must not open the pre-revocation object"
    );

    let mut bad_state = base_commit.state.clone();
    bad_state.revocation_root[0] ^= 1;
    assert!(
        revoke_capability_and_commit(&mut log, &mut tree, &cap, &bad_state, revoke_epoch + 1)
            .is_err(),
        "stale base state must be rejected"
    );

    assert!(
        revoke_capability_and_commit(
            &mut log,
            &mut tree,
            &cap,
            &base_commit.state,
            base_commit.state.epoch,
        )
        .is_err(),
        "revocation epoch must advance"
    );
}

fuzz_target!(|data: &[u8]| {
    fuzz_revoke_capability_and_commit_semantic(data);
});