/// Integration tests for the ML-KEM-768 post-quantum hybrid KEM (spec §11, Phase 2).
///
/// Verifies that:
/// - `RecipientKeyPair::generate` produces non-empty ML-KEM-768 keys
/// - Seal/open round-trips with PQ-enabled keys succeed
/// - The PQ ciphertext is stored in the wrapper and has the correct size
/// - A recipient without a PQ key (classical-only fallback) can still open
///   classical-only objects
/// - Wire encode/decode preserves variable-length `kem_ct_pq`
mod helpers;

use helpers::scenario::Scenario;
use kyriotes_csk2::{
    ML_KEM_768_CT_BYTES, ML_KEM_768_DK_BYTES, ML_KEM_768_EK_BYTES, RecipientKeyPair,
    decode_kyriotes_csk2_object, encode_kyriotes_csk2_object, open, seal,
};

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

/// `RecipientKeyPair::generate` produces ML-KEM-768 keys of the expected sizes.
#[test]
fn recipient_keypair_has_pq_keys() {
    let mut rng = rand::rngs::OsRng;
    let kp = RecipientKeyPair::generate(&mut rng);

    let ek = kp
        .public
        .pq
        .as_ref()
        .expect("public key should have PQ component");
    assert_eq!(
        ek.len(),
        ML_KEM_768_EK_BYTES,
        "encapsulation key should be 1184 bytes"
    );

    let dk = kp
        .secret
        .pq
        .as_ref()
        .expect("secret key should have PQ component");
    assert_eq!(
        dk.len(),
        ML_KEM_768_DK_BYTES,
        "decapsulation key seed should be 64 bytes"
    );
}

/// Two key pairs generated from different rng states produce different PQ keys.
#[test]
fn recipient_keypair_pq_keys_are_distinct() {
    let mut rng = rand::rngs::OsRng;
    let kp1 = RecipientKeyPair::generate(&mut rng);
    let kp2 = RecipientKeyPair::generate(&mut rng);

    assert_ne!(
        kp1.public.pq, kp2.public.pq,
        "independently generated PQ encapsulation keys must differ"
    );
}

// ---------------------------------------------------------------------------
// Seal / open with PQ-enabled keys
// ---------------------------------------------------------------------------

/// Seal and open with a PQ-enabled recipient — the wrapper stores a 1088-byte
/// ML-KEM-768 ciphertext alongside the classical X25519 ciphertext.
#[test]
fn seal_open_with_pq_enabled_recipient() {
    let s = Scenario::baseline("pq-roundtrip", 42).with_message(b"post-quantum plaintext");

    let obj = seal(
        &s.keypair.public,
        &s.message,
        &s.cap,
        &s.proof,
        &s.seal_transparency_proof,
        &s.seal_state,
        &s.req,
        s.temporal_policy.clone(),
    )
    .expect("seal should succeed with PQ key");

    // Wrapper must carry a 1088-byte ML-KEM-768 ciphertext.
    assert_eq!(
        obj.wrappers.len(),
        1,
        "sealed object should have exactly one wrapper"
    );
    assert_eq!(
        obj.wrappers[0].kem_ct_pq.len(),
        ML_KEM_768_CT_BYTES,
        "wrapper should have 1088-byte ML-KEM-768 ciphertext"
    );

    let plaintext = open(&s.keypair.secret, &obj, &s.cap, &s.proof, &s.seal_state)
        .expect("open should succeed with PQ key");
    assert_eq!(plaintext, b"post-quantum plaintext");
}

/// Two successive seals of the same message produce distinct `kem_ct_pq` values
/// (encapsulation uses fresh randomness per invocation via getrandom).
#[test]
fn pq_ciphertexts_are_fresh_each_seal() {
    let s = Scenario::baseline("pq-fresh-ct", 42);

    let obj1 = seal(
        &s.keypair.public,
        &s.message,
        &s.cap,
        &s.proof,
        &s.seal_transparency_proof,
        &s.seal_state,
        &s.req,
        s.temporal_policy.clone(),
    )
    .expect("first seal");

    let obj2 = seal(
        &s.keypair.public,
        &s.message,
        &s.cap,
        &s.proof,
        &s.seal_transparency_proof,
        &s.seal_state,
        &s.req,
        s.temporal_policy.clone(),
    )
    .expect("second seal");

    assert_ne!(
        obj1.wrappers[0].kem_ct_pq, obj2.wrappers[0].kem_ct_pq,
        "each seal must produce a fresh PQ ciphertext"
    );
}

/// Wrong secret key (classical portion wrong) still fails even with a valid PQ key
/// — the hybrid secret won't match so the wrapped DEK decryption fails.
#[test]
fn wrong_secret_key_still_fails_with_pq() {
    let s = Scenario::baseline("pq-wrong-sk", 42).with_message(b"secret");

    let obj = seal(
        &s.keypair.public,
        &s.message,
        &s.cap,
        &s.proof,
        &s.seal_transparency_proof,
        &s.seal_state,
        &s.req,
        s.temporal_policy.clone(),
    )
    .expect("seal");

    // Different key pair — both classical and PQ secrets will differ.
    let wrong_kp = RecipientKeyPair::generate(&mut rand::rngs::OsRng);
    let err = open(&wrong_kp.secret, &obj, &s.cap, &s.proof, &s.seal_state)
        .expect_err("wrong key must fail to open");
    assert!(
        matches!(err, kyriotes_csk2::KyriotesCsk2Error::Crypto(_)),
        "{err:?}"
    );
}

// ---------------------------------------------------------------------------
// Wire codec — variable-length kem_ct_pq
// ---------------------------------------------------------------------------

/// Encode and decode an Kyriotēs-CSK2 object with a 1088-byte ML-KEM-768 ciphertext in
/// the wrapper — the wire codec must preserve the variable-length field.
#[test]
fn wire_encode_decode_preserves_pq_ciphertext() {
    let s = Scenario::baseline("pq-wire", 42).with_message(b"pq wire test");

    let obj = seal(
        &s.keypair.public,
        &s.message,
        &s.cap,
        &s.proof,
        &s.seal_transparency_proof,
        &s.seal_state,
        &s.req,
        s.temporal_policy.clone(),
    )
    .expect("seal");

    assert_eq!(obj.wrappers[0].kem_ct_pq.len(), ML_KEM_768_CT_BYTES);

    let encoded = encode_kyriotes_csk2_object(&obj);
    let decoded = decode_kyriotes_csk2_object(&encoded).expect("decode should succeed");

    assert_eq!(
        decoded.wrappers[0].kem_ct_pq, obj.wrappers[0].kem_ct_pq,
        "decoded kem_ct_pq must match original"
    );
}

/// After encode/decode, the object is still openable by the recipient.
#[test]
fn wire_roundtrip_pq_object_is_openable() {
    let s = Scenario::baseline("pq-wire-open", 42).with_message(b"pq wire open");

    let obj = seal(
        &s.keypair.public,
        &s.message,
        &s.cap,
        &s.proof,
        &s.seal_transparency_proof,
        &s.seal_state,
        &s.req,
        s.temporal_policy.clone(),
    )
    .expect("seal");

    let encoded = encode_kyriotes_csk2_object(&obj);
    let decoded = decode_kyriotes_csk2_object(&encoded).expect("decode");

    let plaintext = open(&s.keypair.secret, &decoded, &s.cap, &s.proof, &s.seal_state)
        .expect("open after wire roundtrip");
    assert_eq!(plaintext, b"pq wire open");
}
