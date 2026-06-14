#![no_main]

use kyriotes_csk2::{
    capability_stamp, hash_policy, issue_capability_and_commit, open, open_and_reseal_and_commit,
    seal_with_verifier, verify_with_verifier, AuthorityCapabilityTree, AuthorityRootKeyPair,
    AuthorityState, Capability, CapabilityIssuanceProof, CapabilityProof, EpochKeyCert,
    EpochSigningKeyPair, InMemoryTransparencyLog, OpenRequest, RecipientKeyPair, Rights,
    StubAuthorityVerifier, TemporalPolicy,
};
use libfuzzer_sys::fuzz_target;
use rand::{rngs::StdRng, SeedableRng};

const VALIDITY_WINDOW: u64 = 512;

fn seed32(data: &[u8], domain: u8) -> [u8; 32] {
    kyriotes_csk2_fuzz::deterministic_seed32(data, domain)
}

fn base_capability(data: &[u8], policy_hash: [u8; 32]) -> Capability {
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&seed32(data.get(8..).unwrap_or_default(), 0x51)[..16]);
    Capability {
        version: 1,
        subject: "reseal-commit-subject".to_string(),
        object_id: format!(
            "reseal-commit-object-{:016x}",
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
    prev_epoch_hash: [u8; 32],
) -> AuthorityState {
    AuthorityState {
        authority_root: tree.authority_root(),
        revocation_root: tree.revocation_root(),
        transparency_root: [0u8; 32],
        epoch,
        authority_id,
        root_pk,
        revocation_count: tree.revocation_count(),
        prev_epoch_hash,
    }
}

fn build_capability_proof(
    tree: &AuthorityCapabilityTree,
    cap: &Capability,
    issuance: CapabilityIssuanceProof,
    state: &AuthorityState,
) -> Option<CapabilityProof> {
    let inclusion = tree.inclusion_proof(cap)?;
    let non_revocation = tree.non_revocation_witness(&capability_stamp(cap, state)).ok()?;

    Some(CapabilityProof {
        inclusion,
        non_revocation,
        issuance,
    })
}

fn issue_commit_and_proof(
    log: &mut InMemoryTransparencyLog,
    tree: &mut AuthorityCapabilityTree,
    cap: &Capability,
    epoch_kp: &EpochSigningKeyPair,
    epoch_cert: &EpochKeyCert,
    state: &AuthorityState,
) -> Option<(CapabilityProof, kyriotes_csk2::TransparencyStateCommit)> {
    let (issuance, commit) = issue_capability_and_commit(log, tree, cap, epoch_kp, epoch_cert, state).ok()?;
    let proof = build_capability_proof(tree, cap, issuance, &commit.state)?;
    Some((proof, commit))
}

fn fuzz_open_and_reseal_and_commit_semantic(data: &[u8]) {
    let data = kyriotes_csk2_fuzz::bounded(data);
    let mut rng = StdRng::from_seed(seed32(data, 0x11));

    let root_kp = AuthorityRootKeyPair::from_seed(seed32(data.get(1..).unwrap_or_default(), 0x21));
    let epoch_kp = EpochSigningKeyPair::from_seed(seed32(data.get(3..).unwrap_or_default(), 0x31));
    let policy_hash = hash_policy(&format!(
        "reseal-commit-policy-{:016x}",
        kyriotes_csk2_fuzz::bytes_to_u64(data.get(5..).unwrap_or_default())
    ));

    let mut tree = AuthorityCapabilityTree::new();
    let cap = base_capability(data, policy_hash);
    tree.add_capability(&cap);

    let open_epoch = (kyriotes_csk2_fuzz::bytes_to_u64(data.get(13..).unwrap_or_default()) % 32)
        .saturating_add(1);
    let reseal_gap = (data.get(21).copied().unwrap_or(0) as u64 % 4).saturating_add(1);
    let reseal_epoch = open_epoch.saturating_add(reseal_gap);
    let authority_id = format!(
        "reseal-commit-fuzz-auth-{}",
        data.first().copied().unwrap_or(0)
    );

    let open_state = authority_state(
        &tree,
        root_kp.verifying_key_bytes(),
        authority_id.clone(),
        open_epoch,
        seed32(data.get(24..).unwrap_or_default(), 0x41),
    );
    let reseal_state = authority_state(
        &tree,
        root_kp.verifying_key_bytes(),
        authority_id,
        reseal_epoch,
        seed32(data.get(56..).unwrap_or_default(), 0x42),
    );

    let mut log = InMemoryTransparencyLog::new();
    let open_epoch_cert = root_kp.issue_epoch_cert(&epoch_kp.verifying_key_bytes(), open_epoch, VALIDITY_WINDOW);
    let Some((open_proof, open_commit)) = issue_commit_and_proof(
        &mut log,
        &mut tree,
        &cap,
        &epoch_kp,
        &open_epoch_cert,
        &open_state,
    ) else {
        return;
    };

    let original_recipient = RecipientKeyPair::generate(&mut rng);
    let verifier = StubAuthorityVerifier;
    let open_request = OpenRequest {
        object_id: cap.object_id.clone(),
        required_rights: Rights::READ,
        policy_hash,
        epoch: open_commit.state.epoch,
    };

    let original = match seal_with_verifier(
        &verifier,
        &original_recipient.public,
        data,
        &cap,
        &open_proof,
        &open_commit.proof,
        &open_commit.state,
        &open_request,
        TemporalPolicy::Current,
    ) {
        Ok(value) => value,
        Err(_) => return,
    };

    let reseal_epoch_cert = root_kp.issue_epoch_cert(&epoch_kp.verifying_key_bytes(), reseal_epoch, VALIDITY_WINDOW);
    let Some((reseal_proof, reseal_commit)) = issue_commit_and_proof(
        &mut log,
        &mut tree,
        &cap,
        &epoch_kp,
        &reseal_epoch_cert,
        &reseal_state,
    ) else {
        return;
    };

    let reseal_request = OpenRequest {
        object_id: cap.object_id.clone(),
        required_rights: Rights::READ,
        policy_hash,
        epoch: reseal_commit.state.epoch,
    };
    let new_recipient = RecipientKeyPair::generate(&mut rng);

    let (resealed, committed) = match open_and_reseal_and_commit(
        &mut log,
        &verifier,
        &original_recipient.secret,
        &new_recipient.public,
        &original,
        &cap,
        &open_proof,
        &open_commit.state,
        &reseal_proof,
        &reseal_commit.state,
        &reseal_request,
        TemporalPolicy::Current,
    ) {
        Ok(value) => value,
        Err(_) => return,
    };

    assert_eq!(committed, reseal_commit, "recommit must stay idempotent for the same seal state");
    assert_ne!(committed.state.transparency_root, [0u8; 32]);
    assert_eq!(resealed.wrappers[0].epoch, committed.state.epoch);

    assert!(
        verify_with_verifier(
            &verifier,
            &resealed,
            &cap,
            &reseal_proof,
            &committed.state,
            &committed.proof,
        )
        .is_ok(),
        "resealed object must verify against the returned commit state"
    );

    assert_eq!(
        open(
            &new_recipient.secret,
            &resealed,
            &cap,
            &reseal_proof,
            &committed.state,
        )
        .expect("new recipient must open resealed object"),
        data
    );
    assert!(
        open(
            &original_recipient.secret,
            &resealed,
            &cap,
            &reseal_proof,
            &committed.state,
        )
        .is_err(),
        "old recipient secret must not decrypt the resealed object"
    );

    let mut tampered_open_state = open_commit.state.clone();
    tampered_open_state.transparency_root[0] ^= 1;
    assert!(
        open_and_reseal_and_commit(
            &mut log,
            &verifier,
            &original_recipient.secret,
            &new_recipient.public,
            &original,
            &cap,
            &open_proof,
            &tampered_open_state,
            &reseal_proof,
            &reseal_commit.state,
            &reseal_request,
            TemporalPolicy::Current,
        )
        .is_err(),
        "tampered open state must fail verification"
    );

    let mut tampered_reseal_request = reseal_request.clone();
    tampered_reseal_request.epoch = tampered_reseal_request.epoch.wrapping_add(1);
    assert!(
        open_and_reseal_and_commit(
            &mut log,
            &verifier,
            &original_recipient.secret,
            &new_recipient.public,
            &original,
            &cap,
            &open_proof,
            &open_commit.state,
            &reseal_proof,
            &reseal_commit.state,
            &tampered_reseal_request,
            TemporalPolicy::Current,
        )
        .is_err(),
        "tampered reseal request epoch must be rejected"
    );
}

fuzz_target!(|data: &[u8]| {
    fuzz_open_and_reseal_and_commit_semantic(data);
});