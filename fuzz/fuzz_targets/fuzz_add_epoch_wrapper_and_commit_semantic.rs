#![no_main]

use kyriotes_csk2::{
    add_epoch_wrapper_and_commit, capability_stamp, hash_policy, issue_capability_and_commit,
    open, seal_with_verifier, verify_with_verifier, AuthorityCapabilityTree, AuthorityRootKeyPair,
    AuthorityState, Capability, CapabilityIssuanceProof, CapabilityProof, InMemoryTransparencyLog,
    OpenRequest, RecipientKeyPair, Rights, StubAuthorityVerifier, TemporalPolicy,
};
use libfuzzer_sys::fuzz_target;
use rand::{rngs::StdRng, SeedableRng};

const VALIDITY_WINDOW: u64 = 512;

fn seed32(data: &[u8], domain: u8) -> [u8; 32] {
    kyriotes_csk2_fuzz::deterministic_seed32(data, domain)
}

fn base_capability(data: &[u8], policy_hash: [u8; 32]) -> Capability {
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&seed32(data.get(8..).unwrap_or_default(), 0x61)[..16]);
    Capability {
        version: 1,
        subject: "epoch-wrapper-commit-subject".to_string(),
        object_id: format!(
            "epoch-wrapper-commit-object-{:016x}",
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
    epoch_kp: &kyriotes_csk2::EpochSigningKeyPair,
    epoch_cert: &kyriotes_csk2::EpochKeyCert,
    state: &AuthorityState,
) -> Option<(CapabilityIssuanceProof, kyriotes_csk2::TransparencyStateCommit)> {
    issue_capability_and_commit(log, tree, cap, epoch_kp, epoch_cert, state).ok()
}

fn fuzz_add_epoch_wrapper_and_commit_semantic(data: &[u8]) {
    let data = kyriotes_csk2_fuzz::bounded(data);
    let mut rng = StdRng::from_seed(seed32(data, 0x13));

    let root_kp = AuthorityRootKeyPair::from_seed(seed32(data.get(1..).unwrap_or_default(), 0x23));
    let epoch_kp = kyriotes_csk2::EpochSigningKeyPair::from_seed(seed32(
        data.get(3..).unwrap_or_default(),
        0x33,
    ));
    let policy_hash = hash_policy(&format!(
        "wrapper-commit-policy-{:016x}",
        kyriotes_csk2_fuzz::bytes_to_u64(data.get(5..).unwrap_or_default())
    ));

    let mut tree = AuthorityCapabilityTree::new();
    let cap = base_capability(data, policy_hash);
    tree.add_capability(&cap);

    let open_epoch = (kyriotes_csk2_fuzz::bytes_to_u64(data.get(13..).unwrap_or_default()) % 32)
        .saturating_add(1);
    let wrapper_gap = (data.get(21).copied().unwrap_or(0) as u64 % 6).saturating_add(1);
    let wrap_epoch = open_epoch.saturating_add(wrapper_gap);
    let authority_id = format!(
        "wrapper-commit-fuzz-auth-{}",
        data.first().copied().unwrap_or(0)
    );

    let open_state = authority_state(
        &tree,
        root_kp.verifying_key_bytes(),
        authority_id.clone(),
        open_epoch,
        seed32(data.get(24..).unwrap_or_default(), 0x43),
    );
    let wrap_state = authority_state(
        &tree,
        root_kp.verifying_key_bytes(),
        authority_id,
        wrap_epoch,
        seed32(data.get(56..).unwrap_or_default(), 0x44),
    );

    let mut log = InMemoryTransparencyLog::new();
    let open_epoch_cert = root_kp.issue_epoch_cert(
        &epoch_kp.verifying_key_bytes(),
        open_epoch,
        VALIDITY_WINDOW,
    );
    let Some((issuance, open_commit)) = issue_commit_and_proof(
        &mut log,
        &mut tree,
        &cap,
        &epoch_kp,
        &open_epoch_cert,
        &open_state,
    ) else {
        return;
    };

    let open_proof = match build_capability_proof(&tree, &cap, issuance.clone(), &open_commit.state)
    {
        Some(value) => value,
        None => return,
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

    let new_recipient = RecipientKeyPair::generate(&mut rng);
    let mut wrapped_object = original.clone();
    let committed = match add_epoch_wrapper_and_commit(
        &mut log,
        &verifier,
        &original_recipient.secret,
        &new_recipient.public,
        &mut wrapped_object,
        &cap,
        &open_proof,
        &open_commit.state,
        &wrap_state,
    ) {
        Ok(value) => value,
        Err(_) => return,
    };

    let to_proof = match build_capability_proof(&tree, &cap, issuance, &committed.state) {
        Some(value) => value,
        None => return,
    };

    assert_ne!(committed.state.transparency_root, [0u8; 32]);

    let wrapper = wrapped_object
        .wrappers
        .iter()
        .find(|w| w.epoch == committed.state.epoch)
        .expect("wrapper must exist at committed epoch");
    assert_eq!(wrapper.transparency_proof, committed.proof);

    assert!(
        verify_with_verifier(
            &verifier,
            &wrapped_object,
            &cap,
            &to_proof,
            &committed.state,
            &committed.proof,
        )
        .is_ok(),
        "wrapped object must verify against the committed transparency proof"
    );

    assert_eq!(
        open(
            &new_recipient.secret,
            &wrapped_object,
            &cap,
            &to_proof,
            &committed.state,
        )
        .expect("new recipient must open wrapped object"),
        data
    );
    assert!(
        open(
            &original_recipient.secret,
            &wrapped_object,
            &cap,
            &to_proof,
            &committed.state,
        )
        .is_err(),
        "old recipient secret must not decrypt the rewrapped object"
    );

    let mut tampered_log_from = log.clone();
    let mut tampered_from_state = open_commit.state.clone();
    tampered_from_state.transparency_root[0] ^= 1;
    assert!(
        add_epoch_wrapper_and_commit(
            &mut tampered_log_from,
            &verifier,
            &original_recipient.secret,
            &new_recipient.public,
            &mut original.clone(),
            &cap,
            &open_proof,
            &tampered_from_state,
            &wrap_state,
        )
        .is_err(),
        "tampered from-state must be rejected"
    );

    let mut tampered_log_to = log.clone();
    let mut tampered_wrap_state = wrap_state.clone();
    tampered_wrap_state.epoch = open_commit.state.epoch;
    assert!(
        add_epoch_wrapper_and_commit(
            &mut tampered_log_to,
            &verifier,
            &original_recipient.secret,
            &new_recipient.public,
            &mut original.clone(),
            &cap,
            &open_proof,
            &open_commit.state,
            &tampered_wrap_state,
        )
        .is_err(),
        "tampered wrapper epoch must be rejected"
    );
}

fuzz_target!(|data: &[u8]| {
    fuzz_add_epoch_wrapper_and_commit_semantic(data);
});