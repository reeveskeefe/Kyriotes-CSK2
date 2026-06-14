#![no_main]

use kyriotes_csk2::{
    capability_leaf_hash, capability_stamp, hash_policy, issue_capability, open_with_verifier,
    rotate_epoch_full, seal_with_verifier, verify_with_verifier, AuthorityCapabilityTree,
    AuthorityRootKeyPair, AuthorityState, Capability, CapabilityProof,
    EpochRotation, EpochSigningKeyPair, InMemoryTransparencyLog, OpenRequest, RecipientKeyPair,
    Rights, TemporalPolicy, TransparencyLog, transparency_log_entry_hash,
};
use libfuzzer_sys::fuzz_target;
use rand::{rngs::StdRng, SeedableRng};

const VALIDITY_WINDOW: u64 = 256;

fn seed32(data: &[u8], domain: u8) -> [u8; 32] {
    kyriotes_csk2_fuzz::deterministic_seed32(data, domain)
}

fn sample_capability(data: &[u8], policy_hash: [u8; 32]) -> Capability {
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&seed32(data.get(8..).unwrap_or_default(), 0xD1)[..16]);
    Capability {
        version: 1,
        subject: "rotation-subject".to_string(),
        object_id: format!(
            "rotation-object-{:016x}",
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

fn state_for(
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

fn issue_and_build_proof(
    tree: &mut AuthorityCapabilityTree,
    cap: &Capability,
    epoch_kp: &EpochSigningKeyPair,
    epoch_cert: &kyriotes_csk2::EpochKeyCert,
    state: &AuthorityState,
) -> CapabilityProof {
    let issuance = issue_capability(tree, cap, epoch_kp, epoch_cert).expect("issue capability");
    let stamp = capability_stamp(cap, state);
    CapabilityProof {
        inclusion: tree.inclusion_proof(cap).expect("cap in tree"),
        non_revocation: tree.non_revocation_witness(&stamp).expect("not revoked"),
        issuance,
    }
}

fn assert_rotation_transcript(rotation: &EpochRotation, prev_hash: &[u8; 32]) {
    let expected = transparency_log_entry_hash(
        prev_hash,
        &rotation.state.authority_root,
        &rotation.state.revocation_root,
        rotation.state.epoch,
        &rotation.epoch_pk,
        &rotation.sigma_e,
    );
    assert_eq!(rotation.chain_hash, expected, "rotation chain hash must match transcript hash");
}

fn fuzz_epoch_rotation_freshness_semantic(data: &[u8]) {
    let data = kyriotes_csk2_fuzz::bounded(data);
    let mut rng = StdRng::from_seed(seed32(data, 0x15));

    let root_kp = AuthorityRootKeyPair::from_seed(seed32(data.get(1..).unwrap_or_default(), 0x25));
    let policy_hash = hash_policy(&format!(
        "rotation-freshness-policy-{:016x}",
        kyriotes_csk2_fuzz::bytes_to_u64(data.get(4..).unwrap_or_default())
    ));
    let cap = sample_capability(data, policy_hash);

    let mut tree = AuthorityCapabilityTree::new();
    tree.add_capability(&cap);

    let base_epoch = (kyriotes_csk2_fuzz::bytes_to_u64(data.get(12..).unwrap_or_default()) % 16)
        .saturating_add(1);
    let authority_id = format!("rotation-fuzz-auth-{}", data.first().copied().unwrap_or(0));
    let mut prev_hash = [0u8; 32];
    let mut current_state = state_for(
        &tree,
        root_kp.verifying_key_bytes(),
        authority_id,
        base_epoch,
        prev_hash,
    );

    let mut log = InMemoryTransparencyLog::new();
    let mut rotations: Vec<EpochRotation> = Vec::new();

    for step in data
        .iter()
        .skip(20)
        .copied()
        .take(kyriotes_csk2_fuzz::MAX_STATEFUL_STRESS_STEPS)
    {
        let next_epoch = current_state
            .epoch
            .saturating_add((step as u64 % 4).saturating_add(1));
        let Ok(rotation) = rotate_epoch_full(
            &mut log,
            &root_kp,
            &current_state,
            next_epoch,
            VALIDITY_WINDOW,
            &prev_hash,
        ) else {
            continue;
        };

        assert_rotation_transcript(&rotation, &prev_hash);
        assert_eq!(
            log.chain_hash_for(&rotation.state.authority_id, rotation.state.epoch),
            Some(rotation.chain_hash),
            "stored chain hash must match committed rotation"
        );

        let verifier = rotation.into_verifier();
        let proof = issue_and_build_proof(
            &mut tree,
            &cap,
            &rotation.epoch_kp,
            &rotation.epoch_cert,
            &rotation.state,
        );
        let recipient = RecipientKeyPair::generate(&mut rng);
        let request = OpenRequest {
            object_id: cap.object_id.clone(),
            required_rights: Rights::READ,
            policy_hash,
            epoch: rotation.state.epoch,
        };

        let object = match seal_with_verifier(
            &verifier,
            &recipient.public,
            data,
            &cap,
            &proof,
            &rotation.transparency_proof,
            &rotation.state,
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
                &rotation.state,
                &rotation.transparency_proof,
            )
            .is_ok()
        );
        assert_eq!(
            open_with_verifier(
                &verifier,
                &recipient.secret,
                &object,
                &cap,
                &proof,
                &rotation.state,
            )
            .expect("fresh rotation-backed object must open"),
            data
        );

        // Stale verifier freshness invariant: a verifier from the previous epoch
        // must not authenticate the new rotation state or object.
        if let Some(previous) = rotations.last() {
            let stale_verifier = previous.into_verifier();
            assert!(
                verify_with_verifier(
                    &stale_verifier,
                    &object,
                    &cap,
                    &proof,
                    &rotation.state,
                    &rotation.transparency_proof,
                )
                .is_err(),
                "stale verifier evidence must not validate a later epoch"
            );
        }

        // Tamper with the stored transcript and prove the derived hash changes.
        let mut tampered_state = rotation.state.clone();
        tampered_state.prev_epoch_hash[0] ^= 1;
        let tampered_chain_hash = transparency_log_entry_hash(
            &tampered_state.prev_epoch_hash,
            &tampered_state.authority_root,
            &tampered_state.revocation_root,
            tampered_state.epoch,
            &rotation.epoch_pk,
            &rotation.sigma_e,
        );
        assert_ne!(
            tampered_chain_hash, rotation.chain_hash,
            "changing prev_epoch_hash must change the transcript hash"
        );

        prev_hash = rotation.chain_hash;
        current_state = rotation.state.clone();
        rotations.push(rotation);
    }

    // Use the last rotation to check that the capability hash material remains stable.
    let _ = capability_leaf_hash(&cap);
    let _ = capability_stamp(&cap, &current_state);
}

fuzz_target!(|data: &[u8]| {
    fuzz_epoch_rotation_freshness_semantic(data);
});
