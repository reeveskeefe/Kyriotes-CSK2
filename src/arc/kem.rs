use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
use ml_kem::{MlKem768, DecapsulationKey, EncapsulationKey, Seed};
use ml_kem::kem::{Decapsulate, Encapsulate, KeyExport, TryKeyInit, FromSeed};

use super::model::{RecipientPublicKey, RecipientSecretKey, ML_KEM_768_CT_BYTES, ML_KEM_768_EK_BYTES, ML_KEM_768_DK_BYTES};

/// Encapsulate to a recipient public key: X25519 ECDH (classical) + ML-KEM-768 (PQ).
///
/// Returns `(ct_classical, ss_classical, ct_pq, ss_pq)` where:
/// - `ct_classical` — ephemeral X25519 public key (32 bytes)
/// - `ss_classical` — X25519 Diffie-Hellman shared secret (32 bytes)
/// - `ct_pq` — ML-KEM-768 ciphertext (1088 bytes) or empty when no PQ key present
/// - `ss_pq` — ML-KEM-768 shared secret (32 bytes) or `[0u8; 32]` when no PQ key
pub fn kem_encaps(
    pk: &RecipientPublicKey,
    rng: &mut (impl RngCore + CryptoRng),
) -> ([u8; 32], [u8; 32], Vec<u8>, [u8; 32]) {
    // Classical X25519
    let ephemeral_sk = EphemeralSecret::random_from_rng(rng);
    let ephemeral_pk = X25519PublicKey::from(&ephemeral_sk);
    let ss = ephemeral_sk.diffie_hellman(&pk.classical);
    let ct_classical: [u8; 32] = ephemeral_pk.to_bytes();
    let ss_classical: [u8; 32] = ss.to_bytes();

    // ML-KEM-768 (PQ) — uses getrandom internally (no rand_core version conflict).
    let (ct_pq, ss_pq) = match &pk.pq {
        Some(ek_bytes) if ek_bytes.len() == ML_KEM_768_EK_BYTES => {
            let key_arr = ml_kem::array::Array::from_slice(ek_bytes.as_ref());
            match EncapsulationKey::<MlKem768>::new(key_arr) {
                Ok(ek) => {
                    let (ct, ss) = ek.encapsulate();
                    let ct_bytes: Vec<u8> = ct.as_slice().to_vec();
                    let ss_bytes: [u8; 32] = ss.as_slice().try_into()
                        .expect("ML-KEM-768 shared secret is 32 bytes");
                    (ct_bytes, ss_bytes)
                }
                Err(_) => (Vec::new(), [0u8; 32]),
            }
        }
        _ => (Vec::new(), [0u8; 32]),
    };

    (ct_classical, ss_classical, ct_pq, ss_pq)
}

/// Decapsulate using the recipient secret key, recovering `(ss_classical, ss_pq)`.
///
/// - `ct_classical` — ephemeral X25519 public key (32 bytes) from the wrapper
/// - `ct_pq` — ML-KEM-768 ciphertext from the wrapper (empty if classical-only)
///
/// Returns `(ss_classical, ss_pq)` where `ss_pq` is `[0u8; 32]` for classical-only objects.
pub fn kem_decaps(
    sk: &RecipientSecretKey,
    ct_classical: &[u8; 32],
    ct_pq: &[u8],
) -> ([u8; 32], [u8; 32]) {
    // Classical X25519
    let ephemeral_pk = X25519PublicKey::from(*ct_classical);
    let ss_classical: [u8; 32] = sk.classical.diffie_hellman(&ephemeral_pk).to_bytes();

    // ML-KEM-768 (PQ)
    let ss_pq = match &sk.pq {
        Some(dk_bytes) if !ct_pq.is_empty() && ct_pq.len() == ML_KEM_768_CT_BYTES
                       && dk_bytes.len() == ML_KEM_768_DK_BYTES => {
            let seed: Seed = Seed::from(**dk_bytes);
            let (dk, _ek) = MlKem768::from_seed(&seed);
            let ct_arr: &ml_kem::kem::Ciphertext<MlKem768> =
                ml_kem::array::Array::from_slice(ct_pq);
            let ss = dk.decapsulate(ct_arr);
            ss.as_slice().try_into().expect("ML-KEM-768 shared secret is 32 bytes")
        }
        _ => [0u8; 32],
    };

    (ss_classical, ss_pq)
}

/// Derive the hybrid shared secret from classical and post-quantum KEM outputs.
///
/// Spec §11: `ss_H = H("ARC-HYBRID-SECRET-v1" || ss_C || ss_Q)`
///
/// When no PQ key is present, `ss_pq` is `[0u8; 32]` (identity element).
pub fn hybrid_secret(ss_c: &[u8; 32], ss_pq: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"ARC-HYBRID-SECRET-v1");
    h.update(ss_c);
    h.update(ss_pq);
    h.finalize().into()
}

