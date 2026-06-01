mod helpers;

use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use helpers::scenario::Scenario;
use kyriotes_csk2::{
    CryptoAuthorityVerifier, KyriotesCsk2Error, seal_with_verifier, verify_with_verifier,
};

#[test]
fn crypto_verifier_rejects_missing_evidence_regression() {
    let s = Scenario::baseline("boundary-missing-evidence", 42).with_message(b"boundary");

    let epoch_root_sig = s.authority.epoch_kp.sign_epoch_root(
        &s.seal_state.authority_root,
        &s.seal_state.revocation_root,
        &s.seal_state.transparency_root,
        s.seal_state.epoch,
        &[0u8; 32],
    );

    let mut seal_verifier = CryptoAuthorityVerifier::with_root_pk(s.authority.root_pk());
    seal_verifier.add_evidence(
        &s.seal_state.authority_id,
        s.seal_state.epoch,
        s.authority.epoch_kp.verifying_key_bytes(),
        epoch_root_sig,
        s.authority.epoch_cert.clone(),
    );

    let object = seal_with_verifier(
        &seal_verifier,
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

    let verifier = CryptoAuthorityVerifier::with_root_pk(s.authority.root_pk());

    let err = verify_with_verifier(
        &verifier,
        &object,
        &s.cap,
        &s.proof,
        &s.seal_state,
        &s.seal_transparency_proof,
    )
    .expect_err("missing evidence should fail verifier boundary");

    assert!(matches!(
        err,
        KyriotesCsk2Error::AuthorityState("missing authority key/signature evidence for epoch")
    ));
}

#[test]
fn crypto_verifier_accepts_valid_evidence_regression() {
    let s = Scenario::baseline("boundary-valid-evidence", 42).with_message(b"boundary");

    let epoch_root_sig = s.authority.epoch_kp.sign_epoch_root(
        &s.seal_state.authority_root,
        &s.seal_state.revocation_root,
        &s.seal_state.transparency_root,
        s.seal_state.epoch,
        &[0u8; 32],
    );

    let mut verifier = CryptoAuthorityVerifier::with_root_pk(s.authority.root_pk());
    verifier.add_evidence(
        &s.seal_state.authority_id,
        s.seal_state.epoch,
        s.authority.epoch_kp.verifying_key_bytes(),
        epoch_root_sig,
        s.authority.epoch_cert.clone(),
    );

    let object = seal_with_verifier(
        &verifier,
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

    verify_with_verifier(
        &verifier,
        &object,
        &s.cap,
        &s.proof,
        &s.seal_state,
        &s.seal_transparency_proof,
    )
    .expect("valid evidence should pass verifier boundary");
}

#[cfg(not(feature = "insecure-stub-verifier"))]
#[test]
fn stub_verifier_unavailable_without_feature_regression() {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("kyriotes-csk2-stub-gate-{ts}"));
    let src_dir = dir.join("src");
    fs::create_dir_all(&src_dir).expect("create temp crate dir");

    let manifest = format!(
        "[package]\nname = \"stub-gate-check\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[dependencies]\nkyriotes-csk2 = {{ path = \"{}\" }}\n",
        env!("CARGO_MANIFEST_DIR")
    );
    fs::write(dir.join("Cargo.toml"), manifest).expect("write Cargo.toml");
    fs::write(
        src_dir.join("main.rs"),
        "use kyriotes_csk2::StubAuthorityVerifier;\nfn main() { let _ = StubAuthorityVerifier; }\n",
    )
    .expect("write main.rs");

    let output = Command::new("cargo")
        .arg("check")
        .current_dir(&dir)
        .output()
        .expect("run cargo check");

    assert!(
        !output.status.success(),
        "StubAuthorityVerifier should be unavailable without feature"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("StubAuthorityVerifier"),
        "stderr should mention StubAuthorityVerifier, got: {stderr}"
    );

    let _ = fs::remove_dir_all(dir);
}

#[cfg(feature = "insecure-stub-verifier")]
#[test]
fn stub_verifier_available_with_feature_regression() {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("kyriotes-csk2-stub-gate-on-{ts}"));
    let src_dir = dir.join("src");
    fs::create_dir_all(&src_dir).expect("create temp crate dir");

    let manifest = format!(
        "[package]\nname = \"stub-gate-check-on\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[dependencies]\nkyriotes-csk2 = {{ path = \"{}\", features = [\"insecure-stub-verifier\"] }}\n",
        env!("CARGO_MANIFEST_DIR")
    );
    fs::write(dir.join("Cargo.toml"), manifest).expect("write Cargo.toml");
    fs::write(
        src_dir.join("main.rs"),
        "use kyriotes_csk2::StubAuthorityVerifier;\nfn main() { let _ = StubAuthorityVerifier; }\n",
    )
    .expect("write main.rs");

    let output = Command::new("cargo")
        .arg("check")
        .current_dir(&dir)
        .output()
        .expect("run cargo check");

    assert!(
        output.status.success(),
        "StubAuthorityVerifier should be available with feature; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let _ = fs::remove_dir_all(dir);
}
