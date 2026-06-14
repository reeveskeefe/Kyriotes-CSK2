#![no_main]

use kyriotes_csk2::{
    capability_leaf_hash, capability_stamp, delegate_capability, hash_policy, issue_capability,
    open_with_verifier, seal_with_verifier, verify_with_verifier, AuthorityCapabilityTree,
    AuthorityRootKeyPair, AuthorityState, Capability, CapabilityProof, EpochSigningKeyPair,
    InMemoryTransparencyLog, OpenRequest, RecipientKeyPair, Rights, StubAuthorityVerifier,
    TemporalPolicy, TransparencyLog,
};
use libfuzzer_sys::fuzz_target;
use rand::{rngs::StdRng, SeedableRng};

fn seed32(data: &[u8], domain: u8) -> [u8; 32] {
    kyriotes_csk2_fuzz::deterministic_seed32(data, domain)
}

fn base_capability(data: &[u8], policy_hash: [u8; 32]) -> Capability {
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&seed32(data.get(8..).unwrap_or_default(), 0x71)[..16]);
    Capability {
        version: 1,
        subject: "delegation-root".to_string(),
        object_id: format!(
            "delegation-chain-object-{:016x}",
            kyriotes_csk2_fuzz::bytes_to_u64(data)
        ),
        rights: Rights::READ.union(Rights::DECRYPT).union(Rights::DELEGATE),
        policy_hash,
        epoch_start: 1,
        epoch_end: 512,
        delegation_depth: 0,
        parent_stamp: [0u8; 32],
        nonce,
    }
}

fn build_state(
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

fn fuzz_delegation_chain_semantic(data: &[u8]) {
    let data = kyriotes_csk2_fuzz::bounded(data);
    let mut rng = StdRng::from_seed(seed32(data, 0x19));

    let root_kp = AuthorityRootKeyPair::from_seed(seed32(data.get(1..).unwrap_or_default(), 0x29));
    let epoch_kp = EpochSigningKeyPair::from_seed(seed32(data.get(3..).unwrap_or_default(), 0x39));
    let policy_hash = hash_policy(&format!(
        "delegation-chain-policy-{:016x}",
        kyriotes_csk2_fuzz::bytes_to_u64(data.get(6..).unwrap_or_default())
    ));

    let mut tree = AuthorityCapabilityTree::new();
    let mut active_cap = base_capability(data, policy_hash);
    tree.add_capability(&active_cap);

    let mut state = build_state(
        &tree,
        root_kp.verifying_key_bytes(),
        format!("delegation-fuzz-auth-{}", data.first().copied().unwrap_or(0)),
        5,
    );
    let epoch_cert = root_kp.issue_epoch_cert(&epoch_kp.verifying_key_bytes(), state.epoch, 1024);

    for selector in data
        .iter()
        .skip(12)
        .copied()
        .take(kyriotes_csk2_fuzz::MAX_STATEFUL_STRESS_STEPS)
    {
        match selector % 5 {
            0 => {
                // Valid delegation path if the parent still carries DELEGATE.
                let window = active_cap.epoch_end.saturating_sub(active_cap.epoch_start);
                let start = active_cap
                    .epoch_start
                    .saturating_add((selector as u64 % (window.saturating_add(1))).min(window));
                let end = start.saturating_add((selector as u64 % 8).min(active_cap.epoch_end - start));
                let requested_rights = if selector & 1 == 0 {
                    Rights::READ.union(Rights::DELEGATE)
                } else {
                    Rights::READ
                };

                if let Ok(next_cap) = delegate_capability(
                    &active_cap,
                    &state,
                    "delegated-subject",
                    requested_rights,
                    start,
                    end,
                    &mut rng,
                ) {
                    tree.add_capability(&next_cap);
                    active_cap = next_cap;
                    state = build_state(
                        &tree,
                        root_kp.verifying_key_bytes(),
                        state.authority_id.clone(),
                        state.epoch,
                    );
                }
            }
            1 => {
                let err = delegate_capability(
                    &active_cap,
                    &state,
                    "escalation",
                    active_cap.rights.union(Rights::WRITE),
                    active_cap.epoch_start,
                    active_cap.epoch_end,
                    &mut rng,
                )
                .expect_err("rights escalation must reject");
                assert!(matches!(err, kyriotes_csk2::KyriotesCsk2Error::InvalidCapability(_)));
            }
            2 => {
                let err = delegate_capability(
                    &active_cap,
                    &state,
                    "window-expansion",
                    Rights::READ,
                    active_cap.epoch_start.saturating_sub(1),
                    active_cap.epoch_end.saturating_add(1),
                    &mut rng,
                )
                .expect_err("epoch expansion must reject");
                assert!(matches!(err, kyriotes_csk2::KyriotesCsk2Error::InvalidCapability(_)));
            }
            3 => {
                let err = delegate_capability(
                    &active_cap,
                    &state,
                    "inverted-window",
                    Rights::READ,
                    active_cap.epoch_end,
                    active_cap.epoch_start,
                    &mut rng,
                )
                .expect_err("inverted window must reject");
                assert!(matches!(err, kyriotes_csk2::KyriotesCsk2Error::InvalidCapability(_)));
            }
            _ => {
                let mut overflow_parent = active_cap.clone();
                overflow_parent.delegation_depth = kyriotes_csk2::MAX_DELEGATION_DEPTH;
                let err = delegate_capability(
                    &overflow_parent,
                    &state,
                    "depth-overflow",
                    Rights::READ,
                    overflow_parent.epoch_start,
                    overflow_parent.epoch_end,
                    &mut rng,
                )
                .expect_err("depth overflow must reject");
                assert!(matches!(err, kyriotes_csk2::KyriotesCsk2Error::InvalidCapability(_)));
            }
        }
    }

    let issuance = match issue_capability(&mut tree, &active_cap, &epoch_kp, &epoch_cert) {
        Ok(value) => value,
        Err(_) => return,
    };
    state = build_state(
        &tree,
        root_kp.verifying_key_bytes(),
        state.authority_id,
        state.epoch,
    );

    let mut log = InMemoryTransparencyLog::new();
    let commit = match log.commit_state(&state) {
        Ok(value) => value,
        Err(_) => return,
    };

    let proof = CapabilityProof {
        inclusion: match tree.inclusion_proof(&active_cap) {
            Some(value) => value,
            None => return,
        },
        non_revocation: match tree.non_revocation_witness(&capability_stamp(&active_cap, &commit.state)) {
            Ok(value) => value,
            Err(_) => return,
        },
        issuance,
    };

    let request = OpenRequest {
        object_id: active_cap.object_id.clone(),
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
        &active_cap,
        &proof,
        &commit.proof,
        &commit.state,
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
            &active_cap,
            &proof,
            &commit.state,
            &commit.proof,
        )
        .is_ok()
    );
    assert_eq!(
        open_with_verifier(
            &verifier,
            &recipient.secret,
            &object,
            &active_cap,
            &proof,
            &commit.state,
        )
        .expect("valid delegated capability should open"),
        data
    );

    // Structural delegation tamper checks that should always reject.
    if active_cap.delegation_depth > 0 {
        let mut tampered = active_cap.clone();
        tampered.parent_stamp = [0u8; 32];
        assert!(
            verify_with_verifier(
                &verifier,
                &object,
                &tampered,
                &proof,
                &commit.state,
                &commit.proof,
            )
            .is_err()
        );
    }

    let mut tampered_direct = active_cap.clone();
    tampered_direct.delegation_depth = 0;
    tampered_direct.parent_stamp = capability_leaf_hash(&active_cap);
    assert!(
        verify_with_verifier(
            &verifier,
            &object,
            &tampered_direct,
            &proof,
            &commit.state,
            &commit.proof,
        )
        .is_err()
    );
}

fuzz_target!(|data: &[u8]| {
    fuzz_delegation_chain_semantic(data);
});
