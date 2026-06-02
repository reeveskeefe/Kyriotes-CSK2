#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct HelperState {
    epoch: u8,
    authority_id: u8,
    authority_root: u8,
    revocation_root: u8,
    transparency_root: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct HelperObject {
    object_id: u8,
    rights: u8,
    policy_hash: u8,
    seal_epoch: u8,
    capability_stamp: u8,
    temporal_policy: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct HelperKemPair {
    ciphertext: u8,
    shared_secret: u8,
}

const CONTEXT_DOMAIN: u8 = 0x41;
const AUTHORITY_DIGEST_DOMAIN: u8 = 0x53;
const KEK_DOMAIN: u8 = 0x67;
const HYBRID_SECRET_DOMAIN: u8 = 0x79;
const AUTHORITY_AAD_DOMAIN: u8 = 0x83;
const PAYLOAD_AAD_DOMAIN: u8 = 0x97;

fn sample_state() -> HelperState {
    HelperState {
        epoch: 3,
        authority_id: 5,
        authority_root: 23,
        revocation_root: 29,
        transparency_root: 31,
    }
}

fn sample_object() -> HelperObject {
    HelperObject {
        object_id: 11,
        rights: 7,
        policy_hash: 19,
        seal_epoch: 3,
        capability_stamp: 37,
        temporal_policy: 1,
    }
}

fn helper_context_hash(object: HelperObject, state: HelperState) -> u8 {
    CONTEXT_DOMAIN
        ^ object.object_id
        ^ object.rights
        ^ object.policy_hash
        ^ state.epoch
        ^ state.authority_root
        ^ state.revocation_root
        ^ state.transparency_root
        ^ object.capability_stamp
        ^ state.authority_id
        ^ object.temporal_policy
}

fn helper_authority_digest(state: HelperState, policy_hash: u8) -> u8 {
    AUTHORITY_DIGEST_DOMAIN
        ^ state.authority_root
        ^ state.revocation_root
        ^ state.transparency_root
        ^ state.epoch
        ^ state.authority_id
        ^ policy_hash
}

fn helper_classical_kem_encaps(recipient_public: u8) -> HelperKemPair {
    HelperKemPair {
        ciphertext: recipient_public ^ 0xA5,
        shared_secret: recipient_public ^ 0x5A,
    }
}

fn helper_classical_kem_decaps(recipient_secret: u8, ciphertext: u8) -> Option<u8> {
    let recipient_public = ciphertext ^ 0xA5;
    if recipient_secret == recipient_public {
        Some(recipient_public ^ 0x5A)
    } else {
        None
    }
}

fn helper_hybrid_shared_secret(classical_secret: u8, pq_secret: u8) -> u8 {
    HYBRID_SECRET_DOMAIN ^ classical_secret ^ pq_secret
}

fn helper_derive_kek(
    hybrid_secret: u8,
    authority_digest: u8,
    context_hash: u8,
    policy_hash: u8,
) -> u8 {
    KEK_DOMAIN ^ hybrid_secret ^ authority_digest ^ context_hash ^ policy_hash
}

fn helper_authority_aad_digest(
    object: HelperObject,
    state: HelperState,
    context_hash: u8,
    classical_kem_ciphertext: u8,
    pq_kem_ciphertext: u8,
) -> u8 {
    AUTHORITY_AAD_DOMAIN
        ^ object.object_id
        ^ object.rights
        ^ object.policy_hash
        ^ state.epoch
        ^ state.authority_root
        ^ state.revocation_root
        ^ state.transparency_root
        ^ context_hash
        ^ object.temporal_policy
        ^ classical_kem_ciphertext
        ^ pq_kem_ciphertext
}

fn helper_payload_aad_digest(object: HelperObject) -> u8 {
    PAYLOAD_AAD_DOMAIN ^ object.object_id ^ object.rights ^ object.policy_hash ^ object.seal_epoch
}

#[kani::proof]
fn helper_surface_context_hash_binds_transparency_root() {
    let object = sample_object();
    let state = sample_state();
    let mut altered = state;
    altered.transparency_root ^= 1;

    assert!(helper_context_hash(object, state) != helper_context_hash(object, altered));
}

#[kani::proof]
fn helper_surface_context_hash_binds_capability_stamp() {
    let mut object = sample_object();
    let state = sample_state();
    let original = helper_context_hash(object, state);
    object.capability_stamp ^= 1;

    assert!(original != helper_context_hash(object, state));
}

#[kani::proof]
fn helper_surface_classical_kem_roundtrip_agrees() {
    let recipient_public: u8 = kani::any();
    let pair = helper_classical_kem_encaps(recipient_public);

    assert!(
        helper_classical_kem_decaps(recipient_public, pair.ciphertext) == Some(pair.shared_secret)
    );
}

#[kani::proof]
fn helper_surface_classical_kem_rejects_wrong_secret() {
    let recipient_public: u8 = kani::any();
    let pair = helper_classical_kem_encaps(recipient_public);

    assert!(helper_classical_kem_decaps(recipient_public ^ 1, pair.ciphertext).is_none());
}

#[kani::proof]
fn helper_surface_classical_kem_rejects_ciphertext_tamper() {
    let recipient_public: u8 = kani::any();
    let pair = helper_classical_kem_encaps(recipient_public);

    assert!(helper_classical_kem_decaps(recipient_public, pair.ciphertext ^ 1).is_none());
}

#[kani::proof]
fn helper_surface_hybrid_secret_binds_classical_and_pq_shares() {
    let classical_secret: u8 = kani::any();
    let pq_secret: u8 = kani::any();
    let original = helper_hybrid_shared_secret(classical_secret, pq_secret);

    assert!(original != helper_hybrid_shared_secret(classical_secret ^ 1, pq_secret));
    assert!(original != helper_hybrid_shared_secret(classical_secret, pq_secret ^ 1));
}

#[kani::proof]
fn helper_surface_derive_kek_is_deterministic() {
    let hybrid_secret: u8 = kani::any();
    let authority_digest: u8 = kani::any();
    let context_hash: u8 = kani::any();
    let policy_hash: u8 = kani::any();

    assert!(
        helper_derive_kek(hybrid_secret, authority_digest, context_hash, policy_hash)
            == helper_derive_kek(hybrid_secret, authority_digest, context_hash, policy_hash)
    );
}

#[kani::proof]
fn helper_surface_derive_kek_binds_context_hash() {
    let hybrid_secret: u8 = kani::any();
    let authority_digest: u8 = kani::any();
    let context_hash: u8 = kani::any();
    let policy_hash: u8 = kani::any();

    assert!(
        helper_derive_kek(hybrid_secret, authority_digest, context_hash, policy_hash)
            != helper_derive_kek(
                hybrid_secret,
                authority_digest,
                context_hash ^ 1,
                policy_hash
            )
    );
}

#[kani::proof]
fn helper_surface_derive_kek_binds_authority_digest() {
    let hybrid_secret: u8 = kani::any();
    let authority_digest: u8 = kani::any();
    let context_hash: u8 = kani::any();
    let policy_hash: u8 = kani::any();

    assert!(
        helper_derive_kek(hybrid_secret, authority_digest, context_hash, policy_hash)
            != helper_derive_kek(
                hybrid_secret,
                authority_digest ^ 1,
                context_hash,
                policy_hash
            )
    );
}

#[kani::proof]
fn helper_surface_authority_aad_binds_context_and_kem_ciphertexts() {
    let object = sample_object();
    let state = sample_state();
    let context_hash = helper_context_hash(object, state);
    let classical_kem_ciphertext: u8 = kani::any();
    let pq_kem_ciphertext: u8 = kani::any();
    let original = helper_authority_aad_digest(
        object,
        state,
        context_hash,
        classical_kem_ciphertext,
        pq_kem_ciphertext,
    );

    assert!(
        original
            != helper_authority_aad_digest(
                object,
                state,
                context_hash ^ 1,
                classical_kem_ciphertext,
                pq_kem_ciphertext,
            )
    );
    assert!(
        original
            != helper_authority_aad_digest(
                object,
                state,
                context_hash,
                classical_kem_ciphertext ^ 1,
                pq_kem_ciphertext,
            )
    );
    assert!(
        original
            != helper_authority_aad_digest(
                object,
                state,
                context_hash,
                classical_kem_ciphertext,
                pq_kem_ciphertext ^ 1,
            )
    );
}

#[kani::proof]
fn helper_surface_payload_aad_binds_object_surface() {
    let mut object = sample_object();
    let original = helper_payload_aad_digest(object);

    object.policy_hash ^= 1;
    assert!(original != helper_payload_aad_digest(object));
}

#[kani::proof]
fn helper_surface_context_and_kek_domains_are_separated() {
    let object = sample_object();
    let state = sample_state();
    let context_hash = helper_context_hash(object, state);
    let authority_digest = helper_authority_digest(state, object.policy_hash);
    let kek = helper_derive_kek(0, authority_digest, context_hash, object.policy_hash);

    assert!(context_hash != kek);
}
