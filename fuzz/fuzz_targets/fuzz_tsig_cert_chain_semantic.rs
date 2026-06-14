#![no_main]

use kyriotes_csk2::{
    capability_leaf_hash, capability_stamp, hash_policy, issue_capability_and_commit,
    open_with_verifier, seal_with_verifier, verify_with_verifier, AuthorityCapabilityTree,
    AuthorityRootKeyPair, AuthorityState, Capability, CapabilityIssuanceProof, CapabilityProof,
    CryptoAuthorityVerifier, EpochSigningKeyPair, InMemoryTransparencyLog, OpenRequest,
    RecipientKeyPair, Rights, TemporalPolicy, ThresholdSignatureSet, tsig_sign,
};
use libfuzzer_sys::fuzz_target;
use rand::{rngs::StdRng, SeedableRng};

const EPOCH: u64 = 7;
const VALIDITY_WINDOW: u64 = 128;

fn seed32(data: &[u8], domain: u8) -> [u8; 32] {
    kyriotes_csk2_fuzz::deterministic_seed32(data, domain)
}

fn sample_capability(data: &[u8], policy_hash: [u8; 32]) -> Capability {
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&seed32(data.get(9..).unwrap_or_default(), 0xC1)[..16]);
    Capability {
        version: 1,
        subject: "tsig-fuzz-subject".to_string(),
        object_id: format!(
            "tsig-fuzz-object-{:016x}",
            kyriotes_csk2_fuzz::bytes_to_u64(data)
        ),
        rights: Rights::READ.union(Rights::DECRYPT),
        policy_hash,
        epoch_start: 1,
        epoch_end: 128,
        delegation_depth: 0,
        parent_stamp: [0u8; 32],
        nonce,
    }
}

fn sample_state(
    tree: &AuthorityCapabilityTree,
    root_pk: [u8; 32],
    authority_id: String,
) -> AuthorityState {
    AuthorityState {
        authority_root: tree.authority_root(),
        revocation_root: tree.revocation_root(),
        transparency_root: [0u8; 32],
        epoch: EPOCH,
        authority_id,
        root_pk,
        revocation_count: tree.revocation_count(),
        prev_epoch_hash: [0u8; 32],
    }
}

fn build_base_verifier(
    state: &AuthorityState,
    root_kp: &AuthorityRootKeyPair,
    tsig_kps: &[EpochSigningKeyPair],
) -> CryptoAuthorityVerifier {
    let authorized_keys: Vec<[u8; 32]> = tsig_kps.iter().map(|kp| kp.verifying_key_bytes()).collect();
    let mut set = ThresholdSignatureSet::new(2);
    set.add(tsig_sign(
        &state.authority_root,
        &state.revocation_root,
        &state.transparency_root,
        state.epoch,
        &state.prev_epoch_hash,
        &tsig_kps[0],
        0,
    ));
    set.add(tsig_sign(
        &state.authority_root,
        &state.revocation_root,
        &state.transparency_root,
        state.epoch,
        &state.prev_epoch_hash,
        &tsig_kps[1],
        1,
    ));

    let cert = root_kp.issue_epoch_cert(&tsig_kps[0].verifying_key_bytes(), state.epoch, VALIDITY_WINDOW);
    let mut verifier = CryptoAuthorityVerifier::with_root_pk(root_kp.verifying_key_bytes());
    verifier.add_evidence_tsig(
        state.authority_id.clone(),
        state.epoch,
        tsig_kps[0].verifying_key_bytes(),
        cert,
        authorized_keys,
        set,
    );
    verifier
}

fn fuzz_tsig_cert_chain_semantic(data: &[u8]) {
    let data = kyriotes_csk2_fuzz::bounded(data);
    let mut rng = StdRng::from_seed(seed32(data, 0x4D));

    let root_kp = AuthorityRootKeyPair::from_seed(seed32(data.get(1..).unwrap_or_default(), 0x21));
    let issuance_kp =
        EpochSigningKeyPair::from_seed(seed32(data.get(3..).unwrap_or_default(), 0x33));
    let tsig_a = EpochSigningKeyPair::from_seed(seed32(data.get(5..).unwrap_or_default(), 0x41));
    let tsig_b = EpochSigningKeyPair::from_seed(seed32(data.get(7..).unwrap_or_default(), 0x42));
    let tsig_c = EpochSigningKeyPair::from_seed(seed32(data.get(11..).unwrap_or_default(), 0x43));
    let tsig_kps = vec![tsig_a, tsig_b, tsig_c];

    let policy_hash = hash_policy(&format!(
        "tsig-cert-chain-policy-{:016x}",
        kyriotes_csk2_fuzz::bytes_to_u64(data.get(13..).unwrap_or_default())
    ));
    let cap = sample_capability(data, policy_hash);

    let mut tree = AuthorityCapabilityTree::new();
    tree.add_capability(&cap);
    let base_state = sample_state(
        &tree,
        root_kp.verifying_key_bytes(),
        format!("tsig-fuzz-authority-{}", data.first().copied().unwrap_or(0)),
    );

    let issuance_cert =
        root_kp.issue_epoch_cert(&issuance_kp.verifying_key_bytes(), base_state.epoch, VALIDITY_WINDOW);
    let mut log = InMemoryTransparencyLog::new();
    let (issuance, commit) = match issue_capability_and_commit(
        &mut log,
        &mut tree,
        &cap,
        &issuance_kp,
        &issuance_cert,
        &base_state,
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

    let mut recipient = RecipientKeyPair::generate(&mut rng);
    if kyriotes_csk2_fuzz::bytes_to_bool(data.get(17..).unwrap_or_default()) {
        recipient.public.pq = None;
        recipient.secret.pq = None;
    }

    let request = OpenRequest {
        object_id: cap.object_id.clone(),
        required_rights: Rights::READ,
        policy_hash,
        epoch: commit.state.epoch,
    };

    let base_verifier = build_base_verifier(&commit.state, &root_kp, &tsig_kps);
    let object = match seal_with_verifier(
        &base_verifier,
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

    assert!(
        verify_with_verifier(
            &base_verifier,
            &object,
            &cap,
            &proof,
            &commit.state,
            &commit.proof,
        )
        .is_ok()
    );
    assert_eq!(
        open_with_verifier(
            &base_verifier,
            &recipient.secret,
            &object,
            &cap,
            &proof,
            &commit.state,
        )
        .expect("valid TSIG-backed scenario must open"),
        data
    );

    for selector in data.iter().copied().take(kyriotes_csk2_fuzz::MAX_STATEFUL_STRESS_STEPS) {
        let mut mutated_state = commit.state.clone();
        let mut authorized_keys: Vec<[u8; 32]> =
            tsig_kps.iter().map(|kp| kp.verifying_key_bytes()).collect();
        let mut set = ThresholdSignatureSet::new(2);
        set.add(tsig_sign(
            &commit.state.authority_root,
            &commit.state.revocation_root,
            &commit.state.transparency_root,
            commit.state.epoch,
            &commit.state.prev_epoch_hash,
            &tsig_kps[0],
            0,
        ));
        set.add(tsig_sign(
            &commit.state.authority_root,
            &commit.state.revocation_root,
            &commit.state.transparency_root,
            commit.state.epoch,
            &commit.state.prev_epoch_hash,
            &tsig_kps[1],
            1,
        ));
        let mut cert =
            root_kp.issue_epoch_cert(&tsig_kps[0].verifying_key_bytes(), commit.state.epoch, VALIDITY_WINDOW);
        let mut transparency_proof = commit.proof.clone();

        match selector % 9 {
            0 => set.threshold = 0,
            1 => set.threshold = 4,
            2 => {
                // Duplicate signer should reduce effective distinct signatures.
                set.partials[1].signer_index = 0;
            }
            3 => {
                set.partials[1].sig[0] ^= 0x80;
            }
            4 => {
                authorized_keys[1][0] ^= 1;
            }
            5 => {
                cert.epoch = cert.epoch.saturating_add(1);
            }
            6 => {
                cert.validity_window = 0;
            }
            7 => {
                mutated_state.prev_epoch_hash[0] ^= 1;
                transparency_proof.leaf_hash = kyriotes_csk2::transparency_leaf_hash(&mutated_state);
            }
            _ => {
                transparency_proof.leaf_hash[0] ^= 1;
            }
        }

        let mut verifier = CryptoAuthorityVerifier::with_root_pk(root_kp.verifying_key_bytes());
        verifier.add_evidence_tsig(
            mutated_state.authority_id.clone(),
            mutated_state.epoch,
            tsig_kps[0].verifying_key_bytes(),
            cert,
            authorized_keys,
            set,
        );

        assert!(
            verify_with_verifier(
                &verifier,
                &object,
                &cap,
                &proof,
                &mutated_state,
                &transparency_proof,
            )
            .is_err()
        );
        assert!(
            open_with_verifier(
                &verifier,
                &recipient.secret,
                &object,
                &cap,
                &proof,
                &mutated_state,
            )
            .is_err()
        );

        // Keep touching this path while mutating verifier evidence.
        let _ = capability_leaf_hash(&cap);
    }
}

fuzz_target!(|data: &[u8]| {
    fuzz_tsig_cert_chain_semantic(data);
});
