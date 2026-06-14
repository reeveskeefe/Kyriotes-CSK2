#![no_main]

use kyriotes_csk2::{
    add_epoch_wrapper_with_verifier, capability_leaf_hash, capability_stamp,
    decode_kyriotes_csk2_object, encode_kyriotes_csk2_object, hash_policy,
    issue_capability_and_commit, open_with_compromise_check_and_verifier, open_with_verifier,
    open_and_reseal_with_verifier, revoke_capability_and_commit, rotate_epoch_full,
    seal_with_verifier, transparency_log_entry_hash, verify_with_compromise_check_and_verifier,
    verify_with_verifier, AuthorityCapabilityTree, AuthorityRootKeyPair, AuthorityState,
    Capability, CapabilityIssuanceProof, CapabilityProof, CryptoAuthorityVerifier,
    EpochSigningKeyPair, InMemoryTransparencyLog, OpenRequest, RecipientKeyPair, Rights,
    TemporalPolicy, TransparencyLog,
};
use libfuzzer_sys::fuzz_target;
use rand::{rngs::StdRng, SeedableRng};

const VALIDITY_WINDOW: u64 = 4096;

fn seed32(data: &[u8], domain: u8) -> [u8; 32] {
    kyriotes_csk2_fuzz::deterministic_seed32(data, domain)
}

fn make_capability(data: &[u8], policy_hash: [u8; 32]) -> Capability {
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&seed32(data.get(12..).unwrap_or_default(), 0xA5)[..16]);
    Capability {
        version: 1,
        subject: "fuzz-subject".to_string(),
        object_id: format!(
            "cross-system-object-{:016x}",
            kyriotes_csk2_fuzz::bytes_to_u64(data)
        ),
        rights: Rights::READ.union(Rights::DECRYPT).union(Rights::DELEGATE),
        policy_hash,
        epoch_start: 1,
        epoch_end: 1_024,
        delegation_depth: 0,
        parent_stamp: [0u8; 32],
        nonce,
    }
}

fn mk_state(
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

fn state_for_epoch(
    history: &[(AuthorityState, kyriotes_csk2::TransparencyProof)],
    epoch: u64,
) -> Option<(AuthorityState, kyriotes_csk2::TransparencyProof)> {
    history
        .iter()
        .find(|(state, _)| state.epoch == epoch)
        .cloned()
}

fn first_wrapper_epoch(object: &kyriotes_csk2::KyriotesCsk2Object) -> Option<u64> {
    object.wrappers.first().map(|wrapper| wrapper.epoch)
}

fn wire_round_trip(
    object: &kyriotes_csk2::KyriotesCsk2Object,
) -> Option<kyriotes_csk2::KyriotesCsk2Object> {
    let encoded = encode_kyriotes_csk2_object(object);
    decode_kyriotes_csk2_object(&encoded).ok()
}

fn fuzz_cross_system_lifecycle_stress(data: &[u8]) {
    let data = kyriotes_csk2_fuzz::bounded(data);
    let seed = seed32(data, 0x31);
    let mut rng = StdRng::from_seed(seed);

    let root_kp = AuthorityRootKeyPair::from_seed(seed32(data.get(1..).unwrap_or_default(), 0x52));
    let epoch1_kp =
        EpochSigningKeyPair::from_seed(seed32(data.get(5..).unwrap_or_default(), 0x73));

    let policy_hash = hash_policy(&format!(
        "cross-system-policy-{:016x}",
        kyriotes_csk2_fuzz::bytes_to_u64(data.get(8..).unwrap_or_default())
    ));
    let cap = make_capability(data, policy_hash);

    let mut tree = AuthorityCapabilityTree::new();
    tree.add_capability(&cap);

    let mut log = InMemoryTransparencyLog::new();
    let authority_id = format!("cross-system-auth-{}", data.first().copied().unwrap_or(0));
    let initial_state = mk_state(
        &tree,
        root_kp.verifying_key_bytes(),
        authority_id,
        1,
        [0u8; 32],
    );

    let epoch1_cert = root_kp.issue_epoch_cert(&epoch1_kp.verifying_key_bytes(), 1, VALIDITY_WINDOW);
    let (issuance, initial_commit) = match issue_capability_and_commit(
        &mut log,
        &mut tree,
        &cap,
        &epoch1_kp,
        &epoch1_cert,
        &initial_state,
    ) {
        Ok(result) => result,
        Err(_) => return,
    };

    let sigma_1 = epoch1_kp.sign_epoch_root(
        &initial_commit.state.authority_root,
        &initial_commit.state.revocation_root,
        &initial_commit.state.transparency_root,
        initial_commit.state.epoch,
        &initial_commit.state.prev_epoch_hash,
    );
    let mut chain_hash = transparency_log_entry_hash(
        &initial_commit.state.prev_epoch_hash,
        &initial_commit.state.authority_root,
        &initial_commit.state.revocation_root,
        initial_commit.state.epoch,
        &epoch1_kp.verifying_key_bytes(),
        &sigma_1,
    );
    log.store_chain_hash(
        &initial_commit.state.authority_id,
        initial_commit.state.epoch,
        chain_hash,
    );

    let mut verifier = CryptoAuthorityVerifier::with_root_pk(root_kp.verifying_key_bytes());
    verifier.add_evidence(
        &initial_commit.state.authority_id,
        initial_commit.state.epoch,
        epoch1_kp.verifying_key_bytes(),
        sigma_1,
        epoch1_cert.clone(),
    );

    let inclusion = match tree.inclusion_proof(&cap) {
        Some(value) => value,
        None => return,
    };
    let stamp = capability_stamp(&cap, &initial_commit.state);
    let non_revocation = match tree.non_revocation_witness(&stamp) {
        Ok(value) => value,
        Err(_) => return,
    };
    let proof = CapabilityProof {
        inclusion,
        non_revocation,
        issuance: CapabilityIssuanceProof {
            sig: issuance.sig,
            epoch_cert: issuance.epoch_cert,
        },
    };

    let mut recipient_a = RecipientKeyPair::generate(&mut rng);
    let mut recipient_b = RecipientKeyPair::generate(&mut rng);
    if data.get(2).copied().unwrap_or(0) & 1 == 1 {
        recipient_a.public.pq = None;
        recipient_a.secret.pq = None;
    }
    if data.get(3).copied().unwrap_or(0) & 1 == 1 {
        recipient_b.public.pq = None;
        recipient_b.secret.pq = None;
    }

    let mut current_owner_is_a = true;
    let message = data.iter().copied().cycle().take(128).collect::<Vec<_>>();

    let request = OpenRequest {
        object_id: cap.object_id.clone(),
        required_rights: Rights::READ,
        policy_hash,
        epoch: initial_commit.state.epoch,
    };

    let mut object = match seal_with_verifier(
        &verifier,
        &recipient_a.public,
        &message,
        &cap,
        &proof,
        &initial_commit.proof,
        &initial_commit.state,
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
            &initial_commit.state,
            &initial_commit.proof,
        )
        .is_ok()
    );
    assert_eq!(
        open_with_verifier(
            &verifier,
            &recipient_a.secret,
            &object,
            &cap,
            &proof,
            &initial_commit.state,
        )
        .expect("freshly sealed object must open"),
        message
    );

    let mut history = vec![(initial_commit.state.clone(), initial_commit.proof.clone())];
    let mut current_state = initial_commit.state;
    let mut current_transparency_proof = initial_commit.proof;

    for step in data
        .iter()
        .skip(24)
        .copied()
        .take(kyriotes_csk2_fuzz::MAX_STATEFUL_STRESS_STEPS)
    {
        match step % 6 {
            0 => {
                let next_epoch = current_state.epoch.saturating_add((step as u64 % 3) + 1);
                let Ok(rotation) = rotate_epoch_full(
                    &mut log,
                    &root_kp,
                    &current_state,
                    next_epoch,
                    VALIDITY_WINDOW,
                    &chain_hash,
                ) else {
                    continue;
                };
                verifier.add_evidence(
                    &rotation.state.authority_id,
                    rotation.state.epoch,
                    rotation.epoch_pk,
                    rotation.sigma_e,
                    rotation.epoch_cert.clone(),
                );
                chain_hash = rotation.chain_hash;
                current_state = rotation.state;
                current_transparency_proof = rotation.transparency_proof;
                history.push((current_state.clone(), current_transparency_proof.clone()));
            }
            1 => {
                let Some(from_epoch) = first_wrapper_epoch(&object) else {
                    continue;
                };
                if from_epoch == current_state.epoch {
                    continue;
                }
                let Some((from_state, _)) = state_for_epoch(&history, from_epoch) else {
                    continue;
                };
                let opener = if current_owner_is_a {
                    &recipient_a.secret
                } else {
                    &recipient_b.secret
                };
                let recipient_pk = if current_owner_is_a {
                    &recipient_a.public
                } else {
                    &recipient_b.public
                };
                if add_epoch_wrapper_with_verifier(
                    &verifier,
                    opener,
                    recipient_pk,
                    &mut object,
                    &cap,
                    &proof,
                    &from_state,
                    &current_state,
                    &current_transparency_proof,
                )
                .is_ok()
                {
                    assert!(
                        verify_with_verifier(
                            &verifier,
                            &object,
                            &cap,
                            &proof,
                            &current_state,
                            &current_transparency_proof,
                        )
                        .is_ok()
                    );
                }
            }
            2 => {
                let Some(open_epoch) = first_wrapper_epoch(&object) else {
                    continue;
                };
                let Some((open_state, _)) = state_for_epoch(&history, open_epoch) else {
                    continue;
                };
                let opener = if current_owner_is_a {
                    &recipient_a.secret
                } else {
                    &recipient_b.secret
                };
                let target_pk = if current_owner_is_a {
                    &recipient_b.public
                } else {
                    &recipient_a.public
                };
                let reseal_req = OpenRequest {
                    object_id: cap.object_id.clone(),
                    required_rights: Rights::READ,
                    policy_hash,
                    epoch: current_state.epoch,
                };
                if let Ok(next_object) = open_and_reseal_with_verifier(
                    &verifier,
                    opener,
                    target_pk,
                    &object,
                    &cap,
                    &proof,
                    &open_state,
                    &proof,
                    &current_transparency_proof,
                    &current_state,
                    &reseal_req,
                    TemporalPolicy::Current,
                ) {
                    object = next_object;
                    current_owner_is_a = !current_owner_is_a;
                }
            }
            3 => {
                let compromise_epoch = current_state.epoch.saturating_sub(step as u64 % 2);
                let notice = root_kp.issue_compromise_notice(
                    &proof.issuance.epoch_cert.epoch_pk,
                    compromise_epoch,
                    current_state.authority_root,
                );
                let notices = [notice];
                if current_state.epoch >= compromise_epoch {
                    assert!(
                        verify_with_compromise_check_and_verifier(
                            &verifier,
                            &object,
                            &cap,
                            &proof,
                            &current_state,
                            &current_transparency_proof,
                            &notices,
                        )
                        .is_err()
                    );
                    let opener = if current_owner_is_a {
                        &recipient_a.secret
                    } else {
                        &recipient_b.secret
                    };
                    assert!(
                        open_with_compromise_check_and_verifier(
                            &verifier,
                            opener,
                            &object,
                            &cap,
                            &proof,
                            &current_state,
                            &notices,
                        )
                        .is_err()
                    );
                }
            }
            4 => {
                let revoke_epoch = current_state.epoch.saturating_add(1);
                let Ok(commit) = revoke_capability_and_commit(
                    &mut log,
                    &mut tree,
                    &cap,
                    &current_state,
                    revoke_epoch,
                ) else {
                    continue;
                };
                let rev_epoch_kp = EpochSigningKeyPair::generate(&mut rng);
                let rev_epoch_pk = rev_epoch_kp.verifying_key_bytes();
                let rev_epoch_cert =
                    root_kp.issue_epoch_cert(&rev_epoch_pk, commit.state.epoch, VALIDITY_WINDOW);
                let rev_sigma = rev_epoch_kp.sign_epoch_root(
                    &commit.state.authority_root,
                    &commit.state.revocation_root,
                    &commit.state.transparency_root,
                    commit.state.epoch,
                    &commit.state.prev_epoch_hash,
                );
                verifier.add_evidence(
                    &commit.state.authority_id,
                    commit.state.epoch,
                    rev_epoch_pk,
                    rev_sigma,
                    rev_epoch_cert,
                );
                chain_hash = transparency_log_entry_hash(
                    &chain_hash,
                    &commit.state.authority_root,
                    &commit.state.revocation_root,
                    commit.state.epoch,
                    &rev_epoch_pk,
                    &rev_sigma,
                );
                current_state = commit.state;
                current_transparency_proof = commit.proof;
                history.push((current_state.clone(), current_transparency_proof.clone()));

                let _ = verify_with_verifier(
                    &verifier,
                    &object,
                    &cap,
                    &proof,
                    &current_state,
                    &current_transparency_proof,
                );
            }
            _ => {
                if let Some(decoded) = wire_round_trip(&object) {
                    object = decoded;
                }
                let mut encoded = encode_kyriotes_csk2_object(&object);
                if !encoded.is_empty() {
                    let index = step as usize % encoded.len();
                    encoded[index] ^= 1;
                    let _ = decode_kyriotes_csk2_object(&encoded);
                }
                // Keep pressure on capability hashing paths while object/state mutate.
                let _ = capability_leaf_hash(&cap);
                let _ = capability_stamp(&cap, &current_state);
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    fuzz_cross_system_lifecycle_stress(data);
});
