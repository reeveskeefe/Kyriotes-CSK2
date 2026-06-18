#![no_main]

use kyriotes_csk2::{
    capability_stamp, hash_policy, issue_capability, open, rotate_epoch_and_commit,
    seal_with_verifier, verify_epoch_cert, verify_with_verifier, AuthorityCapabilityTree,
    AuthorityRootKeyPair, AuthorityState, Capability, CapabilityIssuanceProof, CapabilityProof,
    InMemoryTransparencyLog, OpenRequest, RecipientKeyPair, Rights, StubAuthorityVerifier,
    TemporalPolicy, TransparencyLog,
};
use libfuzzer_sys::fuzz_target;
use rand::{rngs::StdRng, SeedableRng};

const VALIDITY_WINDOW: u64 = 256;

fn seed32(data: &[u8], domain: u8) -> [u8; 32] {
    kyriotes_csk2_fuzz::deterministic_seed32(data, domain)
}

fn base_capability(data: &[u8], policy_hash: [u8; 32]) -> Capability {
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&seed32(data.get(8..).unwrap_or_default(), 0x91)[..16]);
    Capability {
        version: 1,
        subject: "rotate-commit-subject".to_string(),
        object_id: format!(
            "rotate-commit-object-{:016x}",
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
    Some(CapabilityProof {
        inclusion: tree.inclusion_proof(cap)?,
        non_revocation: tree.non_revocation_witness(&capability_stamp(cap, state)).ok()?,
        issuance,
    })
}

fn fuzz_rotate_epoch_and_commit_semantic(data: &[u8]) {
    let data = kyriotes_csk2_fuzz::bounded(data);
    let mut rng = StdRng::from_seed(seed32(data, 0x19));

    let root_kp = AuthorityRootKeyPair::from_seed(seed32(data.get(1..).unwrap_or_default(), 0x29));
    let policy_hash = hash_policy(&format!(
        "rotate-commit-policy-{:016x}",
        kyriotes_csk2_fuzz::bytes_to_u64(data.get(5..).unwrap_or_default())
    ));

    let mut tree = AuthorityCapabilityTree::new();
    let cap = base_capability(data, policy_hash);
    tree.add_capability(&cap);

    let base_epoch = (kyriotes_csk2_fuzz::bytes_to_u64(data.get(13..).unwrap_or_default()) % 24)
        .saturating_add(1);
    let rotation_gap = (data.get(21).copied().unwrap_or(0) as u64 % 8).saturating_add(1);
    let next_epoch = base_epoch.saturating_add(rotation_gap);
    let authority_id = format!("rotate-commit-fuzz-auth-{}", data.first().copied().unwrap_or(0));
    let prev_epoch_hash = seed32(data.get(24..).unwrap_or_default(), 0x49);

    let base_state = authority_state(
        &tree,
        root_kp.verifying_key_bytes(),
        authority_id,
        base_epoch,
        prev_epoch_hash,
    );

    let mut log = InMemoryTransparencyLog::new();
    let (rotated_epoch_kp, rotated_epoch_cert, rotated_commit) = match rotate_epoch_and_commit(
        &mut log,
        &root_kp,
        &base_state,
        next_epoch,
        VALIDITY_WINDOW,
        &prev_epoch_hash,
    ) {
        Ok(value) => value,
        Err(_) => return,
    };

    assert_eq!(rotated_commit.state.epoch, next_epoch);
    assert_ne!(rotated_commit.state.transparency_root, [0u8; 32]);
    assert_eq!(
        log.chain_hash_for(&rotated_commit.state.authority_id, rotated_commit.state.epoch),
        Some(rotated_commit.chain_hash),
        "stored chain hash must match committed rotation"
    );

    verify_epoch_cert(&root_kp.verifying_key_bytes(), &rotated_epoch_cert)
        .expect("rotation cert must verify under root key");

    let issuance = match issue_capability(&mut tree, &cap, &rotated_epoch_kp, &rotated_epoch_cert) {
        Ok(value) => value,
        Err(_) => return,
    };
    let proof = match build_capability_proof(&tree, &cap, issuance, &rotated_commit.state) {
        Some(value) => value,
        None => return,
    };

    let recipient = RecipientKeyPair::generate(&mut rng);
    let verifier = StubAuthorityVerifier;
    let request = OpenRequest {
        object_id: cap.object_id.clone(),
        required_rights: Rights::READ,
        policy_hash,
        epoch: rotated_commit.state.epoch,
    };

    let object = match seal_with_verifier(
        &verifier,
        &recipient.public,
        data,
        &cap,
        &proof,
        &rotated_commit.proof,
        &rotated_commit.state,
        &request,
        TemporalPolicy::Current,
    ) {
        Ok(value) => value,
        Err(_) => return,
    };

    assert!(
        verify_with_verifier(
            &verifier,
            &object,
            &cap,
            &proof,
            &rotated_commit.state,
            &rotated_commit.proof,
        )
        .is_ok(),
        "rotated state must verify"
    );
    assert_eq!(
        open(
            &recipient.secret,
            &object,
            &cap,
            &proof,
            &rotated_commit.state,
        )
        .expect("rotated state must open"),
        data
    );

    let mut tampered_prev_hash = prev_epoch_hash;
    tampered_prev_hash[0] ^= 1;
    let mut other_log = InMemoryTransparencyLog::new();
    let other_rotation = rotate_epoch_and_commit(
        &mut other_log,
        &root_kp,
        &base_state,
        next_epoch,
        VALIDITY_WINDOW,
        &tampered_prev_hash,
    );
    if let Ok((_, _, other_commit)) = other_rotation {
        assert_ne!(
            other_commit.chain_hash, rotated_commit.chain_hash,
            "changing prev_epoch_hash must change the chain hash"
        );
    }

    let mut conflicting_base_state = base_state.clone();
    conflicting_base_state.authority_root[0] ^= 1;
    assert!(
        rotate_epoch_and_commit(
            &mut log,
            &root_kp,
            &conflicting_base_state,
            next_epoch,
            VALIDITY_WINDOW,
            &prev_epoch_hash,
        )
        .is_err(),
        "conflicting rotation state at the same epoch must be rejected"
    );
}

fuzz_target!(|data: &[u8]| {
    fuzz_rotate_epoch_and_commit_semantic(data);
});