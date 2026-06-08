#![no_main]

use kyriotes_csk2::{
    capability_leaf_hash, capability_stamp, decode_kyriotes_csk2_object,
    encode_kyriotes_csk2_object, hash_policy, open, seal, verify, AuthorityCapabilityTree,
    AuthorityRootKeyPair, AuthorityState, Capability, CapabilityIssuanceProof, CapabilityProof,
    EpochSigningKeyPair, InMemoryTransparencyLog, OpenRequest, RecipientKeyPair, Rights,
    TemporalPolicy, TransparencyLog,
};
use libfuzzer_sys::fuzz_target;
use rand::{rngs::StdRng, SeedableRng};

const MAX_MESSAGE_LEN: usize = 512;

struct SemanticScenario {
    keypair: RecipientKeyPair,
    state: AuthorityState,
    cap: Capability,
    proof: CapabilityProof,
    request: OpenRequest,
    transparency_proof: kyriotes_csk2::TransparencyProof,
    temporal_policy: TemporalPolicy,
    message: Vec<u8>,
}

fn seed32(data: &[u8]) -> [u8; 32] {
    let mut seed = [0u8; 32];
    let take = data.len().min(seed.len());
    seed[..take].copy_from_slice(&data[..take]);
    for (index, byte) in seed.iter_mut().enumerate().skip(take) {
        *byte = (index as u8).wrapping_mul(37).wrapping_add(11);
    }
    seed
}

fn scenario(data: &[u8]) -> Option<SemanticScenario> {
    let seed = seed32(data);
    let mut rng = StdRng::from_seed(seed);
    let epoch = (kyriotes_csk2_fuzz::bytes_to_u64(data) % 32).saturating_add(1);
    let object_id = format!(
        "fuzz-object-{:016x}",
        kyriotes_csk2_fuzz::bytes_to_u64(data.get(8..).unwrap_or_default())
    );
    let policy_hash = hash_policy(&format!(
        "fuzz-policy-{:016x}",
        kyriotes_csk2_fuzz::bytes_to_u64(data.get(16..).unwrap_or_default())
    ));
    let rights = Rights::READ.union(Rights::DECRYPT);
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&seed[..16]);

    let cap = Capability {
        version: 1,
        subject: "fuzz-recipient".to_string(),
        object_id: object_id.clone(),
        rights,
        policy_hash,
        epoch_start: 1,
        epoch_end: 64,
        delegation_depth: 0,
        parent_stamp: [0u8; 32],
        nonce,
    };

    let root_keypair = AuthorityRootKeyPair::generate(&mut rng);
    let epoch_keypair = EpochSigningKeyPair::generate(&mut rng);
    let epoch_cert = root_keypair.issue_epoch_cert(&epoch_keypair.verifying_key_bytes(), epoch, 10);
    let mut tree = AuthorityCapabilityTree::new();
    tree.add_capability(&cap);

    let seed_state = AuthorityState {
        authority_root: tree.authority_root(),
        revocation_root: tree.revocation_root(),
        transparency_root: [0u8; 32],
        epoch,
        authority_id: format!("fuzz-authority-{}", seed[31]),
        root_pk: root_keypair.verifying_key_bytes(),
        revocation_count: tree.revocation_count(),
        prev_epoch_hash: [0u8; 32],
    };
    let mut log = InMemoryTransparencyLog::new();
    let commit = log.commit_state(&seed_state).ok()?;
    let inclusion = tree.inclusion_proof(&cap)?;
    let stamp = capability_stamp(&cap, &commit.state);
    let non_revocation = tree.non_revocation_witness(&stamp).ok()?;
    let leaf_hash = capability_leaf_hash(&cap);
    let issuance = CapabilityIssuanceProof {
        sig: epoch_keypair.sign_capability_issuance(
            &leaf_hash,
            &commit.state.authority_root,
            epoch_cert.epoch,
        ),
        epoch_cert,
    };
    let proof = CapabilityProof {
        inclusion,
        non_revocation,
        issuance,
    };
    let request = OpenRequest {
        object_id,
        required_rights: Rights::READ,
        policy_hash,
        epoch,
    };
    let temporal_policy = match seed[30] % 4 {
        0 => TemporalPolicy::Historical(epoch),
        1 => TemporalPolicy::Current,
        2 => TemporalPolicy::Window {
            start: epoch.saturating_sub(1),
            end: epoch.saturating_add(1),
        },
        _ => TemporalPolicy::ResealRequired {
            after: epoch.saturating_add(1),
        },
    };
    let message_start = data.len().min(24);
    let message_end = data
        .len()
        .min(message_start.saturating_add(MAX_MESSAGE_LEN));
    let message = data[message_start..message_end].to_vec();

    Some(SemanticScenario {
        keypair: RecipientKeyPair::generate(&mut rng),
        state: commit.state,
        cap,
        proof,
        request,
        transparency_proof: commit.proof,
        temporal_policy,
        message,
    })
}

fn assert_rejects(scenario: &SemanticScenario, object: &kyriotes_csk2::KyriotesCsk2Object) {
    assert!(open(
        &scenario.keypair.secret,
        object,
        &scenario.cap,
        &scenario.proof,
        &scenario.state,
    )
    .is_err());
}

fn fuzz_semantic_verify_and_open(data: &[u8]) {
    let Some(scenario) = scenario(data) else {
        return;
    };
    let Ok(object) = seal(
        &scenario.keypair.public,
        &scenario.message,
        &scenario.cap,
        &scenario.proof,
        &scenario.transparency_proof,
        &scenario.state,
        &scenario.request,
        scenario.temporal_policy.clone(),
    ) else {
        return;
    };

    assert_eq!(
        open(
            &scenario.keypair.secret,
            &object,
            &scenario.cap,
            &scenario.proof,
            &scenario.state,
        )
        .expect("valid fuzz scenario must open"),
        scenario.message
    );
    assert!(verify(
        &object,
        &scenario.cap,
        &scenario.proof,
        &scenario.state,
        &scenario.transparency_proof,
    )
    .is_ok());

    let encoded = encode_kyriotes_csk2_object(&object);
    let decoded = decode_kyriotes_csk2_object(&encoded).expect("encoded valid object must decode");
    assert_eq!(decoded, object);
    assert_eq!(
        open(
            &scenario.keypair.secret,
            &decoded,
            &scenario.cap,
            &scenario.proof,
            &scenario.state,
        )
        .expect("decoded valid object must open"),
        scenario.message
    );

    let selector = data.first().copied().unwrap_or(0) % 14;
    let mut tampered = object.clone();
    match selector {
        0 => tampered.object_id.push('x'),
        1 => tampered.required_rights = tampered.required_rights.union(Rights::WRITE),
        2 => tampered.policy_hash[0] ^= 1,
        3 => tampered.seal_epoch = tampered.seal_epoch.wrapping_add(1),
        4 => {
            tampered.temporal_policy = match tampered.temporal_policy {
                TemporalPolicy::Historical(_) => TemporalPolicy::Current,
                TemporalPolicy::Current => TemporalPolicy::Historical(tampered.seal_epoch),
                TemporalPolicy::Window { .. } => TemporalPolicy::Current,
                TemporalPolicy::ResealRequired { .. } => TemporalPolicy::Current,
            };
        }
        5 => tampered.payload_nonce[0] ^= 1,
        6 => tampered.payload_ciphertext[0] ^= 1,
        7 => tampered.wrappers[0].epoch = tampered.wrappers[0].epoch.wrapping_add(1),
        8 => tampered.wrappers[0].kem_ct_classical[0] ^= 1,
        9 => tampered.wrappers[0].kem_ct_pq[0] ^= 1,
        10 => tampered.wrappers[0].wrap_nonce[0] ^= 1,
        11 => tampered.wrappers[0].wrapped_dek[0] ^= 1,
        12 => tampered.wrappers[0].context_hash[0] ^= 1,
        _ => tampered.wrappers[0].capability_stamp[0] ^= 1,
    }
    assert_rejects(&scenario, &tampered);

    let tampered_wire = encode_kyriotes_csk2_object(&tampered);
    let decoded_tamper = decode_kyriotes_csk2_object(&tampered_wire)
        .expect("semantic tamper should remain structurally decodable");
    assert_rejects(&scenario, &decoded_tamper);
}

fuzz_target!(|data: &[u8]| {
    fuzz_semantic_verify_and_open(kyriotes_csk2_fuzz::bounded(data));
});
