mod helpers;

use arc_core::{
    ArcError, ArcObject, AuthorityWrapper, DecodeLimits, DecodeProfile, InMemoryTransparencyLog,
    Rights, TemporalPolicy, TransparencyLog, TransparencyProof, decode_arc_object,
    decode_arc_object_with_limits, decode_profile_from_env, decode_profile_from_env_value,
    encode_arc_object, seal,
};
use helpers::scenario::Scenario;
use helpers::state::sample_state;

fn sample_transparency_proof() -> TransparencyProof {
    let mut log = InMemoryTransparencyLog::new();

    let mut state0 = sample_state(10);
    state0.authority_id = "auth-wire-0".to_string();
    log.commit_state(&state0).expect("state0 should commit");

    let mut state1 = sample_state(11);
    state1.authority_id = "auth-wire-1".to_string();
    let commit = log.commit_state(&state1).expect("state1 should commit");

    commit.proof
}

#[test]
fn arc_object_roundtrip_wire_codec() {
    let s = Scenario::baseline("wire-roundtrip", 42)
        .with_temporal_policy(TemporalPolicy::Historical(42))
        .with_message(b"wire payload");

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

    let encoded = encode_arc_object(&object);
    let decoded = decode_arc_object(&encoded).expect("decode should succeed");

    assert_eq!(decoded, object);
}

#[test]
fn arc_object_decode_rejects_bad_magic() {
    let mut bytes = encode_arc_object(&arc_core::ArcObject {
        version: 1,
        suite: "ARC-DEV".to_string(),
        object_id: "o".to_string(),
        required_rights: arc_core::Rights::READ,
        policy_hash: [1u8; 32],
        seal_epoch: 1,
        temporal_policy: TemporalPolicy::Current,
        authority_root: [2u8; 32],
        revocation_root: [3u8; 32],
        payload_nonce: [4u8; 12],
        payload_ciphertext: vec![5, 6, 7],
        wrappers: vec![],
    });

    bytes[0] ^= 0xFF;

    let err = decode_arc_object(&bytes).expect_err("bad magic must fail");
    assert!(matches!(err, ArcError::Parse("invalid ARC object magic")));
}

#[test]
fn arc_object_decode_rejects_truncated_input() {
    let s = Scenario::baseline("wire-truncated", 42).with_message(b"truncate me");

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

    let mut encoded = encode_arc_object(&object);
    encoded.truncate(encoded.len() - 1);

    let err = decode_arc_object(&encoded).expect_err("truncated payload should fail");
    assert!(matches!(err, ArcError::Parse(_)));
}

#[test]
fn arc_object_decode_rejects_oversized_payload_field() {
    let object = ArcObject {
        version: 1,
        suite: "ARC-DEV".to_string(),
        object_id: "obj".to_string(),
        required_rights: Rights::READ,
        policy_hash: [1u8; 32],
        seal_epoch: 1,
        temporal_policy: TemporalPolicy::Current,
        authority_root: [2u8; 32],
        revocation_root: [3u8; 32],
        payload_nonce: [4u8; 12],
        payload_ciphertext: vec![0u8; (8 * 1024 * 1024) + 1],
        wrappers: vec![],
    };

    let encoded = encode_arc_object(&object);
    let err = decode_arc_object(&encoded).expect_err("oversized payload must fail");
    assert!(matches!(
        err,
        ArcError::Parse("field exceeds maximum allowed length")
    ));
}

#[test]
fn arc_object_decode_rejects_oversized_wrapper_count() {
    let base_wrapper = AuthorityWrapper {
        epoch: 1,
        kem_ct_classical: [9u8; 32],
        kem_ct_pq: [8u8; 32].to_vec(),
        wrap_nonce: [7u8; 12],
        wrapped_dek: vec![6u8; 48],
        context_hash: [5u8; 32],
        capability_stamp: [4u8; 32],
        transparency_proof: sample_transparency_proof(),
    };

    let object = ArcObject {
        version: 1,
        suite: "ARC-DEV".to_string(),
        object_id: "obj".to_string(),
        required_rights: Rights::READ,
        policy_hash: [1u8; 32],
        seal_epoch: 1,
        temporal_policy: TemporalPolicy::Current,
        authority_root: [2u8; 32],
        revocation_root: [3u8; 32],
        payload_nonce: [4u8; 12],
        payload_ciphertext: vec![5u8; 32],
        wrappers: vec![base_wrapper; 1025],
    };

    let encoded = encode_arc_object(&object);
    let err = decode_arc_object(&encoded).expect_err("oversized wrapper count must fail");
    assert!(matches!(
        err,
        ArcError::Parse("wrapper count exceeds maximum allowed")
    ));
}

#[test]
fn arc_object_decode_rejects_oversized_wrapped_dek_field() {
    let wrapper = AuthorityWrapper {
        epoch: 1,
        kem_ct_classical: [9u8; 32],
        kem_ct_pq: [8u8; 32].to_vec(),
        wrap_nonce: [7u8; 12],
        wrapped_dek: vec![6u8; 4097],
        context_hash: [5u8; 32],
        capability_stamp: [4u8; 32],
        transparency_proof: sample_transparency_proof(),
    };

    let object = ArcObject {
        version: 1,
        suite: "ARC-DEV".to_string(),
        object_id: "obj".to_string(),
        required_rights: Rights::READ,
        policy_hash: [1u8; 32],
        seal_epoch: 1,
        temporal_policy: TemporalPolicy::Current,
        authority_root: [2u8; 32],
        revocation_root: [3u8; 32],
        payload_nonce: [4u8; 12],
        payload_ciphertext: vec![5u8; 32],
        wrappers: vec![wrapper],
    };

    let encoded = encode_arc_object(&object);
    let err = decode_arc_object(&encoded).expect_err("oversized wrapped DEK must fail");
    assert!(matches!(
        err,
        ArcError::Parse("field exceeds maximum allowed length")
    ));
}

#[test]
fn arc_object_decode_with_limits_rejects_when_custom_max_payload_is_tighter() {
    let object = ArcObject {
        version: 1,
        suite: "ARC-DEV".to_string(),
        object_id: "obj".to_string(),
        required_rights: Rights::READ,
        policy_hash: [1u8; 32],
        seal_epoch: 1,
        temporal_policy: TemporalPolicy::Current,
        authority_root: [2u8; 32],
        revocation_root: [3u8; 32],
        payload_nonce: [4u8; 12],
        payload_ciphertext: vec![0u8; 64],
        wrappers: vec![],
    };

    let encoded = encode_arc_object(&object);
    let limits = DecodeLimits {
        max_payload_ciphertext_len: 32,
        ..DecodeLimits::default()
    };

    let err = decode_arc_object_with_limits(&encoded, limits)
        .expect_err("custom tighter payload limit should reject");
    assert!(matches!(
        err,
        ArcError::Parse("field exceeds maximum allowed length")
    ));
}

#[test]
fn arc_object_decode_with_limits_allows_relaxed_wrapped_dek_limit() {
    let wrapper = AuthorityWrapper {
        epoch: 1,
        kem_ct_classical: [9u8; 32],
        kem_ct_pq: [8u8; 32].to_vec(),
        wrap_nonce: [7u8; 12],
        wrapped_dek: vec![6u8; 5000],
        context_hash: [5u8; 32],
        capability_stamp: [4u8; 32],
        transparency_proof: sample_transparency_proof(),
    };

    let object = ArcObject {
        version: 1,
        suite: "ARC-DEV".to_string(),
        object_id: "obj".to_string(),
        required_rights: Rights::READ,
        policy_hash: [1u8; 32],
        seal_epoch: 1,
        temporal_policy: TemporalPolicy::Current,
        authority_root: [2u8; 32],
        revocation_root: [3u8; 32],
        payload_nonce: [4u8; 12],
        payload_ciphertext: vec![5u8; 32],
        wrappers: vec![wrapper],
    };

    let encoded = encode_arc_object(&object);
    let limits = DecodeLimits {
        max_wrapped_dek_len: 6000,
        ..DecodeLimits::default()
    };

    let decoded = decode_arc_object_with_limits(&encoded, limits)
        .expect("relaxed custom wrapped DEK limit should allow decode");
    assert_eq!(decoded.wrappers.len(), 1);
    assert_eq!(decoded.wrappers[0].wrapped_dek.len(), 5000);
}

#[test]
fn embedded_profile_rejects_large_payload() {
    let object = ArcObject {
        version: 1,
        suite: "ARC-DEV".to_string(),
        object_id: "obj".to_string(),
        required_rights: Rights::READ,
        policy_hash: [1u8; 32],
        seal_epoch: 1,
        temporal_policy: TemporalPolicy::Current,
        authority_root: [2u8; 32],
        revocation_root: [3u8; 32],
        payload_nonce: [4u8; 12],
        payload_ciphertext: vec![0u8; (256 * 1024) + 1],
        wrappers: vec![],
    };

    let encoded = encode_arc_object(&object);
    let err = decode_arc_object_with_limits(&encoded, DecodeProfile::Embedded.limits())
        .expect_err("embedded profile should reject payload larger than 256 KiB");
    assert!(matches!(
        err,
        ArcError::Parse("field exceeds maximum allowed length")
    ));
}

#[test]
fn server_profile_allows_larger_wrapped_dek() {
    let wrapper = AuthorityWrapper {
        epoch: 1,
        kem_ct_classical: [9u8; 32],
        kem_ct_pq: [8u8; 32].to_vec(),
        wrap_nonce: [7u8; 12],
        wrapped_dek: vec![6u8; 10 * 1024],
        context_hash: [5u8; 32],
        capability_stamp: [4u8; 32],
        transparency_proof: sample_transparency_proof(),
    };

    let object = ArcObject {
        version: 1,
        suite: "ARC-DEV".to_string(),
        object_id: "obj".to_string(),
        required_rights: Rights::READ,
        policy_hash: [1u8; 32],
        seal_epoch: 1,
        temporal_policy: TemporalPolicy::Current,
        authority_root: [2u8; 32],
        revocation_root: [3u8; 32],
        payload_nonce: [4u8; 12],
        payload_ciphertext: vec![5u8; 32],
        wrappers: vec![wrapper],
    };

    let encoded = encode_arc_object(&object);
    let decoded = decode_arc_object_with_limits(&encoded, DecodeProfile::Server.limits())
        .expect("server profile should allow wrapped DEK up to 16 KiB");
    assert_eq!(decoded.wrappers[0].wrapped_dek.len(), 10 * 1024);
}

#[test]
fn arc_object_decode_rejects_transparency_proof_with_too_many_siblings() {
    let mut log = InMemoryTransparencyLog::new();
    for i in 0..16u64 {
        let mut st = sample_state(200 + i);
        st.authority_id = format!("auth-depth-{i}");
        log.commit_state(&st)
            .expect("state should commit into transparency log");
    }

    let mut target = sample_state(999);
    target.authority_id = "auth-depth-target".to_string();
    let commit = log
        .commit_state(&target)
        .expect("target state should commit");

    let wrapper = AuthorityWrapper {
        epoch: 1,
        kem_ct_classical: [9u8; 32],
        kem_ct_pq: [8u8; 32].to_vec(),
        wrap_nonce: [7u8; 12],
        wrapped_dek: vec![6u8; 48],
        context_hash: [5u8; 32],
        capability_stamp: [4u8; 32],
        transparency_proof: commit.proof,
    };

    let object = ArcObject {
        version: 1,
        suite: "ARC-DEV".to_string(),
        object_id: "obj".to_string(),
        required_rights: Rights::READ,
        policy_hash: [1u8; 32],
        seal_epoch: 1,
        temporal_policy: TemporalPolicy::Current,
        authority_root: [2u8; 32],
        revocation_root: [3u8; 32],
        payload_nonce: [4u8; 12],
        payload_ciphertext: vec![5u8; 32],
        wrappers: vec![wrapper],
    };

    let encoded = encode_arc_object(&object);
    let limits = DecodeLimits {
        max_transparency_siblings: 2,
        ..DecodeLimits::default()
    };

    let err = decode_arc_object_with_limits(&encoded, limits)
        .expect_err("proof path longer than configured max_transparency_siblings must fail");
    assert!(matches!(
        err,
        ArcError::Parse("transparency sibling count exceeds maximum allowed")
    ));
}

#[test]
fn decode_profile_maps_to_expected_limits() {
    assert_eq!(
        DecodeProfile::Embedded.limits(),
        DecodeLimits::embedded_profile()
    );
    assert_eq!(
        DecodeProfile::Strict.limits(),
        DecodeLimits::strict_default()
    );
    assert_eq!(
        DecodeProfile::Server.limits(),
        DecodeLimits::server_profile()
    );
}

#[test]
fn decode_profile_parses_cli_values() {
    assert_eq!(
        DecodeProfile::from_cli_value("embedded"),
        Some(DecodeProfile::Embedded)
    );
    assert_eq!(
        DecodeProfile::from_cli_value(" EMBED "),
        Some(DecodeProfile::Embedded)
    );
    assert_eq!(
        DecodeProfile::from_cli_value("strict"),
        Some(DecodeProfile::Strict)
    );
    assert_eq!(
        DecodeProfile::from_cli_value("default"),
        Some(DecodeProfile::Strict)
    );
    assert_eq!(
        DecodeProfile::from_cli_value("SERVER"),
        Some(DecodeProfile::Server)
    );
    assert_eq!(
        DecodeProfile::from_cli_value("srv"),
        Some(DecodeProfile::Server)
    );
    assert_eq!(DecodeProfile::from_cli_value("unknown"), None);
}

#[test]
fn decode_profile_from_str_supports_env_cli_paths() {
    use core::str::FromStr;

    let strict = DecodeProfile::from_str("strict").expect("strict profile should parse");
    assert_eq!(strict, DecodeProfile::Strict);

    let err = DecodeProfile::from_str("nope").expect_err("unknown profile should fail");
    assert!(matches!(err, ArcError::Parse("unknown decode profile")));
}

#[test]
fn decode_profile_from_env_value_falls_back_to_strict() {
    assert_eq!(decode_profile_from_env_value(None), DecodeProfile::Strict);
    assert_eq!(
        decode_profile_from_env_value(Some("invalid")),
        DecodeProfile::Strict
    );
    assert_eq!(
        decode_profile_from_env_value(Some("embedded")),
        DecodeProfile::Embedded
    );
}

#[test]
fn decode_profile_from_env_missing_var_defaults_to_strict() {
    let profile = decode_profile_from_env("ARC_DECODE_PROFILE_DOES_NOT_EXIST_FOR_TEST");
    assert_eq!(profile, DecodeProfile::Strict);
}
