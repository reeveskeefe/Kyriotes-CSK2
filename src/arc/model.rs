use sha2::{Digest, Sha256};
use rand::{CryptoRng, RngCore};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::core::rights::Rights;
use crate::core::temporal::TemporalPolicy;
use crate::encoding::codec::{put_bytes, put_rights, put_str, put_temporal_policy, put_u64};

/// Recipient public key (classical X25519; PQ slot reserved for Phase 2).
#[derive(Clone, Debug)]
pub struct RecipientPublicKey {
    pub classical: X25519PublicKey,
}

/// Recipient secret key (classical X25519; PQ slot reserved for Phase 2).
pub struct RecipientSecretKey {
    pub classical: StaticSecret,
}

/// A matched public/secret keypair for an ARC recipient.
pub struct RecipientKeyPair {
    pub public: RecipientPublicKey,
    pub secret: RecipientSecretKey,
}

impl RecipientKeyPair {
    pub fn generate(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        let secret = StaticSecret::random_from_rng(rng);
        let public = X25519PublicKey::from(&secret);
        Self {
            public: RecipientPublicKey { classical: public },
            secret: RecipientSecretKey { classical: secret },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capability {
    pub subject: String,
    pub object_id: String,
    pub rights: Rights,
    pub policy_hash: [u8; 32],
    pub epoch_start: u64,
    pub epoch_end: u64,
    pub nonce: [u8; 16],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityProof {
    pub inclusion_valid: bool,
    pub non_revoked: bool,
    pub issued_signature_valid: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransparencyProof {
    pub leaf_hash: [u8; 32],
    pub sibling_hashes: Vec<[u8; 32]>,
    pub leaf_index: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityState {
    pub authority_root: [u8; 32],
    pub revocation_root: [u8; 32],
    pub transparency_root: [u8; 32],
    pub epoch: u64,
    pub authority_id: String,
    pub epoch_signature_valid: bool,
    pub epoch_key_cert_valid: bool,
    pub transparency_inclusion_valid: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenRequest {
    pub object_id: String,
    pub required_rights: Rights,
    pub policy_hash: [u8; 32],
    pub epoch: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityWrapper {
    pub epoch: u64,
    pub kem_ct_classical: [u8; 32],
    pub kem_ct_pq: [u8; 32],
    pub wrap_nonce: [u8; 12],
    pub wrapped_dek: Vec<u8>,
    pub context_hash: [u8; 32],
    pub capability_stamp: [u8; 32],
    pub transparency_proof: TransparencyProof,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArcObject {
    pub version: u16,
    pub suite: String,
    pub object_id: String,
    pub required_rights: Rights,
    pub policy_hash: [u8; 32],
    pub seal_epoch: u64,
    pub temporal_policy: TemporalPolicy,
    pub authority_root: [u8; 32],
    pub revocation_root: [u8; 32],
    pub payload_nonce: [u8; 12],
    pub payload_ciphertext: Vec<u8>,
    pub wrappers: Vec<AuthorityWrapper>,
}

pub fn hash_policy(policy: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ARC-POLICY-v1");
    hasher.update(policy.as_bytes());
    hasher.finalize().into()
}

pub fn capability_leaf_hash(cap: &Capability) -> [u8; 32] {
    let mut enc = Vec::new();
    put_str(&mut enc, &cap.subject);
    put_str(&mut enc, &cap.object_id);
    put_rights(&mut enc, cap.rights);
    put_bytes(&mut enc, &cap.policy_hash);
    put_u64(&mut enc, cap.epoch_start);
    put_u64(&mut enc, cap.epoch_end);
    put_bytes(&mut enc, &cap.nonce);

    let mut hasher = Sha256::new();
    hasher.update(b"ARC-CAPABILITY-LEAF-v1");
    hasher.update(enc);
    hasher.finalize().into()
}

pub fn capability_stamp(cap: &Capability, state: &AuthorityState) -> [u8; 32] {
    let leaf = capability_leaf_hash(cap);
    let mut hasher = Sha256::new();
    hasher.update(b"ARC-CAPABILITY-STAMP-v1");
    hasher.update(leaf);
    hasher.update(state.authority_root);
    hasher.update(state.epoch.to_le_bytes());
    hasher.update(state.authority_id.as_bytes());
    hasher.finalize().into()
}

pub fn transparency_leaf_hash(state: &AuthorityState) -> [u8; 32] {
    let mut enc = Vec::new();
    put_bytes(&mut enc, &state.authority_root);
    put_bytes(&mut enc, &state.revocation_root);
    put_u64(&mut enc, state.epoch);
    put_str(&mut enc, &state.authority_id);

    let mut hasher = Sha256::new();
    hasher.update(b"ARC-TRANSPARENCY-LEAF-v1");
    hasher.update(enc);
    hasher.finalize().into()
}

pub fn context_hash(
    object_id: &str,
    required_rights: Rights,
    policy_hash: [u8; 32],
    state: &AuthorityState,
    cap_stamp: [u8; 32],
    temporal_policy: &TemporalPolicy,
) -> [u8; 32] {
    let mut enc = Vec::new();
    put_str(&mut enc, object_id);
    put_rights(&mut enc, required_rights);
    put_bytes(&mut enc, &policy_hash);
    put_u64(&mut enc, state.epoch);
    put_bytes(&mut enc, &state.authority_root);
    put_bytes(&mut enc, &state.revocation_root);
    put_bytes(&mut enc, &state.transparency_root);
    put_bytes(&mut enc, &cap_stamp);
    put_str(&mut enc, &state.authority_id);
    put_temporal_policy(&mut enc, temporal_policy);

    let mut hasher = Sha256::new();
    hasher.update(b"ARC-CONTEXT-v1");
    hasher.update(enc);
    hasher.finalize().into()
}
