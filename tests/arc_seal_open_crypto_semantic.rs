mod helpers;

use arc_core::{ArcError, open, seal};
use helpers::scenario::Scenario;

fn sealed_object(label: &str, message: &[u8]) -> (Scenario, arc_core::ArcObject) {
    let s = Scenario::baseline(label, 42).with_message(message);
    let object = seal(
        &s.keypair.public,
        &s.message,
        &s.cap,
        &s.proof,
        &s.seal_transparency_proof,
        &s.seal_state,
        &s.req,
        s.temporal_policy.clone(),
    )
    .expect("seal should succeed");
    (s, object)
}

#[test]
fn production_seal_open_composed_roundtrip_returns_message() {
    let (s, object) = sealed_object("composed-roundtrip", b"semantic message");

    let opened = open(&s.keypair.secret, &object, &s.cap, &s.proof, &s.open_state)
        .expect("open should succeed");

    assert_eq!(opened, b"semantic message");
}

#[test]
fn production_open_rejects_payload_ciphertext_tamper() {
    let (s, mut object) = sealed_object("payload-tamper", b"semantic message");
    object.payload_ciphertext[0] ^= 1;

    let err = open(&s.keypair.secret, &object, &s.cap, &s.proof, &s.open_state)
        .expect_err("payload ciphertext tamper must reject");

    assert!(matches!(err, ArcError::Crypto(_)));
}

#[test]
fn production_open_rejects_wrapped_dek_tamper() {
    let (s, mut object) = sealed_object("wrapped-dek-tamper", b"semantic message");
    object.wrappers[0].wrapped_dek[0] ^= 1;

    let err = open(&s.keypair.secret, &object, &s.cap, &s.proof, &s.open_state)
        .expect_err("wrapped DEK tamper must reject");

    assert!(matches!(err, ArcError::Crypto(_)));
}

#[test]
fn production_open_rejects_policy_hash_tamper() {
    let (s, mut object) = sealed_object("policy-tamper", b"semantic message");
    object.policy_hash[0] ^= 1;

    let err = open(&s.keypair.secret, &object, &s.cap, &s.proof, &s.open_state)
        .expect_err("policy hash tamper must reject");

    assert!(matches!(err, ArcError::InvalidCapability(_)));
}

#[test]
fn production_open_rejects_context_hash_tamper() {
    let (s, mut object) = sealed_object("context-tamper", b"semantic message");
    object.wrappers[0].context_hash[0] ^= 1;

    let err = open(&s.keypair.secret, &object, &s.cap, &s.proof, &s.open_state)
        .expect_err("context hash tamper must reject");

    assert!(matches!(err, ArcError::AuthorityState(_)));
}

#[test]
fn production_open_rejects_classical_kem_ciphertext_tamper() {
    let (s, mut object) = sealed_object("classical-kem-tamper", b"semantic message");
    object.wrappers[0].kem_ct_classical[0] ^= 1;

    let err = open(&s.keypair.secret, &object, &s.cap, &s.proof, &s.open_state)
        .expect_err("classical KEM ciphertext tamper must reject");

    assert!(matches!(err, ArcError::Crypto(_)));
}

#[test]
fn production_open_rejects_pq_kem_ciphertext_tamper() {
    let (s, mut object) = sealed_object("pq-kem-tamper", b"semantic message");
    assert!(
        !object.wrappers[0].kem_ct_pq.is_empty(),
        "scenario recipient should include PQ key material"
    );
    object.wrappers[0].kem_ct_pq[0] ^= 1;

    let err = open(&s.keypair.secret, &object, &s.cap, &s.proof, &s.open_state)
        .expect_err("PQ KEM ciphertext tamper must reject");

    assert!(matches!(err, ArcError::Crypto(_)));
}
