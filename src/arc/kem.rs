use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

use super::model::{RecipientPublicKey, RecipientSecretKey};

/// Encapsulate to a recipient public key using ephemeral X25519 ECDH.
///
/// Returns `(ct_classical, ss_classical)` where:
/// - `ct_classical` is the ephemeral public key (32 bytes, stored in the wrapper)
/// - `ss_classical` is the X25519 shared secret (32 bytes, used as KEM input)
///
/// A fresh ephemeral keypair is generated per call, so every wrapper has a
/// distinct ciphertext even for the same recipient.
pub fn kem_encaps(
    pk: &RecipientPublicKey,
    rng: &mut (impl RngCore + CryptoRng),
) -> ([u8; 32], [u8; 32]) {
    let ephemeral_sk = EphemeralSecret::random_from_rng(rng);
    let ephemeral_pk = X25519PublicKey::from(&ephemeral_sk);
    let ss = ephemeral_sk.diffie_hellman(&pk.classical);

    let ct_classical: [u8; 32] = ephemeral_pk.to_bytes();
    let ss_classical: [u8; 32] = ss.to_bytes();

    (ct_classical, ss_classical)
}

/// Decapsulate from a wrapper's stored `ct_classical` using the recipient
/// secret key, recovering the same `ss_classical` that was produced during seal.
pub fn kem_decaps(sk: &RecipientSecretKey, ct_classical: &[u8; 32]) -> [u8; 32] {
    let ephemeral_pk = X25519PublicKey::from(*ct_classical);
    sk.classical.diffie_hellman(&ephemeral_pk).to_bytes()
}

/// Derive the hybrid shared secret from the classical KEM output.
///
/// Spec §11: `ss_H = H("ARC-HYBRID-SECRET-v1" || ss_C)`
///
/// The domain tag and input structure are stable — Phase 2 will append `ss_Q`
/// (the PQ KEM output) without changing the prefix.
pub fn hybrid_secret(ss_c: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"ARC-HYBRID-SECRET-v1");
    h.update(ss_c);
    h.finalize().into()
}
