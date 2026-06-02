mod helpers;

use helpers::scenario::Scenario;
use kyriotes_csk2::{
    KyriotesCsk2Error, TemporalPolicy, decode_kyriotes_csk2_object, encode_kyriotes_csk2_object,
    open, seal,
};

fn sealed_object(label: &str, message: &[u8]) -> (Scenario, kyriotes_csk2::KyriotesCsk2Object) {
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

    assert!(matches!(err, KyriotesCsk2Error::Crypto(_)));
}

#[test]
fn production_open_rejects_wrapped_dek_tamper() {
    let (s, mut object) = sealed_object("wrapped-dek-tamper", b"semantic message");
    object.wrappers[0].wrapped_dek[0] ^= 1;

    let err = open(&s.keypair.secret, &object, &s.cap, &s.proof, &s.open_state)
        .expect_err("wrapped DEK tamper must reject");

    assert!(matches!(err, KyriotesCsk2Error::Crypto(_)));
}

#[test]
fn production_open_rejects_policy_hash_tamper() {
    let (s, mut object) = sealed_object("policy-tamper", b"semantic message");
    object.policy_hash[0] ^= 1;

    let err = open(&s.keypair.secret, &object, &s.cap, &s.proof, &s.open_state)
        .expect_err("policy hash tamper must reject");

    assert!(matches!(err, KyriotesCsk2Error::InvalidCapability(_)));
}

#[test]
fn production_open_rejects_context_hash_tamper() {
    let (s, mut object) = sealed_object("context-tamper", b"semantic message");
    object.wrappers[0].context_hash[0] ^= 1;

    let err = open(&s.keypair.secret, &object, &s.cap, &s.proof, &s.open_state)
        .expect_err("context hash tamper must reject");

    assert!(matches!(err, KyriotesCsk2Error::AuthorityState(_)));
}

#[test]
fn production_open_rejects_classical_kem_ciphertext_tamper() {
    let (s, mut object) = sealed_object("classical-kem-tamper", b"semantic message");
    object.wrappers[0].kem_ct_classical[0] ^= 1;

    let err = open(&s.keypair.secret, &object, &s.cap, &s.proof, &s.open_state)
        .expect_err("classical KEM ciphertext tamper must reject");

    assert!(matches!(err, KyriotesCsk2Error::Crypto(_)));
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

    assert!(matches!(err, KyriotesCsk2Error::Crypto(_)));
}

#[test]
fn production_open_rejects_wrapper_swapped_from_other_object() {
    let (s, mut object) = sealed_object("wrapper-swap-a", b"semantic message");
    let (_other_s, other_object) = sealed_object("wrapper-swap-b", b"other semantic message");

    object.wrappers[0] = other_object.wrappers[0].clone();

    let err = open(&s.keypair.secret, &object, &s.cap, &s.proof, &s.open_state)
        .expect_err("wrapper from another object must reject");

    assert!(
        matches!(
            err,
            KyriotesCsk2Error::AuthorityState(_) | KyriotesCsk2Error::Crypto(_)
        ),
        "expected context or crypto rejection, got {err:?}"
    );
}

#[test]
fn production_open_rejects_missing_epoch_wrapper() {
    let s = Scenario::baseline("missing-epoch-wrapper", 42)
        .with_temporal_policy(TemporalPolicy::Current)
        .with_message(b"semantic message");
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
    let open_state50 = s.make_state_at_epoch(50);

    let err = open(&s.keypair.secret, &object, &s.cap, &s.proof, &open_state50)
        .expect_err("current policy requires a wrapper for the open epoch");

    assert!(matches!(err, KyriotesCsk2Error::MissingWrapper));
}

#[test]
fn production_open_rejects_wrong_epoch_wrapper() {
    let (s, mut object) = sealed_object("wrong-epoch-wrapper", b"semantic message");
    object.wrappers[0].epoch = 43;

    let err = open(&s.keypair.secret, &object, &s.cap, &s.proof, &s.open_state)
        .expect_err("wrong wrapper epoch must not satisfy epoch 42 open");

    assert!(matches!(err, KyriotesCsk2Error::MissingWrapper));
}

#[test]
fn production_open_rejects_swapped_capability_proof() {
    let (s, object) = sealed_object("swapped-proof-a", b"semantic message");
    let (other_s, _other_object) = sealed_object("swapped-proof-b", b"other semantic message");

    let err = open(
        &s.keypair.secret,
        &object,
        &s.cap,
        &other_s.proof,
        &s.open_state,
    )
    .expect_err("capability proof from another capability must reject");

    assert!(matches!(err, KyriotesCsk2Error::InvalidCapability(_)));
}

#[test]
fn production_open_rejects_swapped_authority_state() {
    let (s, object) = sealed_object("swapped-state-a", b"semantic message");
    let (other_s, _other_object) = sealed_object("swapped-state-b", b"other semantic message");

    let err = open(
        &s.keypair.secret,
        &object,
        &s.cap,
        &s.proof,
        &other_s.open_state,
    )
    .expect_err("authority state from another object must reject");

    assert!(
        matches!(
            err,
            KyriotesCsk2Error::AuthorityState(_) | KyriotesCsk2Error::InvalidCapability(_)
        ),
        "expected authority or capability rejection, got {err:?}"
    );
}

#[test]
fn production_open_rejects_stale_transparency_root() {
    let (s, object) = sealed_object("stale-transparency-root", b"semantic message");
    let mut stale_state = s.open_state.clone();
    stale_state.transparency_root[0] ^= 1;

    let err = open(&s.keypair.secret, &object, &s.cap, &s.proof, &stale_state)
        .expect_err("stale transparency root must reject");

    assert!(matches!(err, KyriotesCsk2Error::AuthorityState(_)));
}

#[test]
fn production_open_rejects_altered_temporal_policy() {
    let (s, mut object) = sealed_object("altered-temporal-policy", b"semantic message");
    object.temporal_policy = TemporalPolicy::Current;

    let err = open(&s.keypair.secret, &object, &s.cap, &s.proof, &s.open_state)
        .expect_err("temporal policy tamper must reject");

    assert!(
        matches!(
            err,
            KyriotesCsk2Error::AuthorityState(_) | KyriotesCsk2Error::Crypto(_)
        ),
        "expected context or crypto rejection, got {err:?}"
    );
}

#[test]
fn plausible_decoded_object_with_policy_tamper_rejects_before_plaintext_recovery() {
    let (s, mut object) = sealed_object("plausible-wire-policy-tamper", b"semantic message");
    object.policy_hash[0] ^= 1;

    let encoded = encode_kyriotes_csk2_object(&object);
    let decoded = decode_kyriotes_csk2_object(&encoded)
        .expect("tampered but well-formed object bytes should decode");

    let err = open(&s.keypair.secret, &decoded, &s.cap, &s.proof, &s.open_state)
        .expect_err("plausible decoded policy tamper must reject");

    assert!(matches!(err, KyriotesCsk2Error::InvalidCapability(_)));
}

#[test]
fn plausible_decoded_object_with_temporal_policy_tamper_rejects_before_plaintext_recovery() {
    let (s, mut object) = sealed_object("plausible-wire-temporal-tamper", b"semantic message");
    object.temporal_policy = TemporalPolicy::Current;

    let encoded = encode_kyriotes_csk2_object(&object);
    let decoded = decode_kyriotes_csk2_object(&encoded)
        .expect("tampered but well-formed object bytes should decode");

    let err = open(&s.keypair.secret, &decoded, &s.cap, &s.proof, &s.open_state)
        .expect_err("plausible decoded temporal-policy tamper must reject");

    assert!(
        matches!(
            err,
            KyriotesCsk2Error::AuthorityState(_) | KyriotesCsk2Error::Crypto(_)
        ),
        "expected context or crypto rejection, got {err:?}"
    );
}
