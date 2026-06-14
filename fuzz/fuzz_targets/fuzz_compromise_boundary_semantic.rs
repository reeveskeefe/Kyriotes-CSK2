#![no_main]

use kyriotes_csk2::{
    capability_stamp, hash_policy, issue_capability_and_commit, open_with_compromise_check_and_verifier,
    seal_with_verifier, verify_with_compromise_check_and_verifier, AuthorityCapabilityTree,
    AuthorityRootKeyPair, AuthorityState, Capability, CapabilityIssuanceProof, CapabilityProof,
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
    nonce.copy_from_slice(&seed32(data.get(8..).unwrap_or_default(), 0x81)[..16]);
    Capability {
        version: 1,
        subject: "compromise-subject".to_string(),
        object_id: format!(
            "compromise-object-{:016x}",
            kyriotes_csk2_fuzz::bytes_to_u64(data)
        ),
        rights: Rights::READ.union(Rights::DECRYPT),
        policy_hash,
        epoch_start: 1,
        epoch_end: 2048,
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

fn fuzz_compromise_boundary_semantic(data: &[u8]) {
    let data = kyriotes_csk2_fuzz::bounded(data);
    let mut rng = StdRng::from_seed(seed32(data, 0x11));

    let root_kp = AuthorityRootKeyPair::from_seed(seed32(data.get(1..).unwrap_or_default(), 0x21));
    let epoch_kp = EpochSigningKeyPair::from_seed(seed32(data.get(3..).unwrap_or_default(), 0x31));
    let policy_hash = hash_policy(&format!(
        "compromise-policy-{:016x}",
        kyriotes_csk2_fuzz::bytes_to_u64(data.get(5..).unwrap_or_default())
    ));

    let mut tree = AuthorityCapabilityTree::new();
    let cap = base_capability(data, policy_hash);
    tree.add_capability(&cap);

    let epoch = (kyriotes_csk2_fuzz::bytes_to_u64(data.get(13..).unwrap_or_default()) % 32)
        .saturating_add(2);
    let state_seed = authority_state(
        &tree,
        root_kp.verifying_key_bytes(),
        format!("compromise-fuzz-auth-{}", data.first().copied().unwrap_or(0)),
        epoch,
    );

    let epoch_cert = root_kp.issue_epoch_cert(&epoch_kp.verifying_key_bytes(), epoch, VALIDITY_WINDOW);
    let mut log = InMemoryTransparencyLog::new();
    let (issuance, commit) = match issue_capability_and_commit(
        &mut log,
        &mut tree,
        &cap,
        &epoch_kp,
        &epoch_cert,
        &state_seed,
    ) {
        Ok(value) => value,
        Err(_) => return,
    };

    let proof = CapabilityProof {
        inclusion: match tree.inclusion_proof(&cap) {
            Some(value) => value,
            None => return,
        },
        non_revocation: match tree.non_revocation_witness(&capability_stamp(&cap, &commit.state)) {
            Ok(value) => value,
            Err(_) => return,
        },
        issuance: CapabilityIssuanceProof {
            sig: issuance.sig,
            epoch_cert: issuance.epoch_cert,
        },
    };

    let request = OpenRequest {
        object_id: cap.object_id.clone(),
        required_rights: Rights::READ,
        policy_hash,
        epoch: commit.state.epoch,
    };
    let recipient = RecipientKeyPair::generate(&mut rng);
    let verifier = StubAuthorityVerifier;

    let object = match seal_with_verifier(
        &verifier,
        &recipient.public,
        data,
        &cap,
        &proof,
        &commit.proof,
        &commit.state,
        &request,
        TemporalPolicy::Current,
    ) {
        Ok(value) => value,
        Err(_) => return,
    };

    // Security baseline: empty notice set must not fail closed.
    assert!(
        verify_with_compromise_check_and_verifier(
            &verifier,
            &object,
            &cap,
            &proof,
            &commit.state,
            &commit.proof,
            &[],
        )
        .is_ok()
    );

    let matching_notice = root_kp.issue_compromise_notice(
        &proof.issuance.epoch_cert.epoch_pk,
        kyriotes_csk2_fuzz::bytes_to_u64(data.get(21..).unwrap_or_default()) % (commit.state.epoch + 4),
        commit.state.authority_root,
    );

    // Non-matching key notice should not block legitimate opens/verifies.
    let mut other_pk = proof.issuance.epoch_cert.epoch_pk;
    other_pk[0] ^= 1;
    let non_matching_notice = root_kp.issue_compromise_notice(&other_pk, commit.state.epoch, [0xAA; 32]);

    // Invalid notice signature must force fail-closed for compromise-check APIs.
    let mut invalid_sig_notice = matching_notice.clone();
    invalid_sig_notice.signature[0] ^= 0x80;

    let mixed_notices = vec![non_matching_notice.clone(), matching_notice.clone()];
    let mixed_with_invalid = vec![matching_notice.clone(), invalid_sig_notice.clone()];

    let enforce_reject = commit.state.epoch >= matching_notice.compromised_epoch;

    if enforce_reject {
        assert!(
            open_with_compromise_check_and_verifier(
                &verifier,
                &recipient.secret,
                &object,
                &cap,
                &proof,
                &commit.state,
                &mixed_notices,
            )
            .is_err()
        );
        assert!(
            verify_with_compromise_check_and_verifier(
                &verifier,
                &object,
                &cap,
                &proof,
                &commit.state,
                &commit.proof,
                &mixed_notices,
            )
            .is_err()
        );
    } else {
        assert!(
            open_with_compromise_check_and_verifier(
                &verifier,
                &recipient.secret,
                &object,
                &cap,
                &proof,
                &commit.state,
                &mixed_notices,
            )
            .is_ok()
        );
        assert!(
            verify_with_compromise_check_and_verifier(
                &verifier,
                &object,
                &cap,
                &proof,
                &commit.state,
                &commit.proof,
                &mixed_notices,
            )
            .is_ok()
        );
    }

    // Hard fail-closed invariant: any invalid signature in notice set must reject.
    assert!(
        open_with_compromise_check_and_verifier(
            &verifier,
            &recipient.secret,
            &object,
            &cap,
            &proof,
            &commit.state,
            &mixed_with_invalid,
        )
        .is_err()
    );
    assert!(
        verify_with_compromise_check_and_verifier(
            &verifier,
            &object,
            &cap,
            &proof,
            &commit.state,
            &commit.proof,
            &mixed_with_invalid,
        )
        .is_err()
    );
}

fuzz_target!(|data: &[u8]| {
    fuzz_compromise_boundary_semantic(data);
});
