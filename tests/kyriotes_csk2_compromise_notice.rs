use kyriotes_csk2::{
    AuthorityRootKeyPair, CompromiseNotice, EpochSigningKeyPair, KyriotesCsk2Error,
    check_epoch_not_compromised, compromise_notice_signing_message, verify_compromise_notice,
};
use rand::rngs::OsRng;

fn make_notice() -> (AuthorityRootKeyPair, EpochSigningKeyPair, CompromiseNotice) {
    let root = AuthorityRootKeyPair::generate(&mut OsRng);
    let epoch_kp = EpochSigningKeyPair::generate(&mut OsRng);
    let notice = root.issue_compromise_notice(&epoch_kp.verifying_key_bytes(), 42, [0xABu8; 32]);
    (root, epoch_kp, notice)
}

// ---------------------------------------------------------------------------
// Signing message
// ---------------------------------------------------------------------------

#[test]
fn compromise_notice_signing_message_is_deterministic() {
    let pk = [0x11u8; 32];
    let recovery = [0x22u8; 32];
    let a = compromise_notice_signing_message(&pk, 7, &recovery);
    let b = compromise_notice_signing_message(&pk, 7, &recovery);
    assert_eq!(a, b);
    assert!(a.starts_with(b"KYRIOTES-CSK2-COMPROMISE-v1"));
}

// ---------------------------------------------------------------------------
// Issue / verify roundtrip
// ---------------------------------------------------------------------------

#[test]
fn compromise_notice_verify_roundtrip() {
    let (root, _, notice) = make_notice();
    verify_compromise_notice(&root.verifying_key_bytes(), &notice)
        .expect("valid notice must verify");
}

// ---------------------------------------------------------------------------
// Rejection cases
// ---------------------------------------------------------------------------

#[test]
fn compromise_notice_rejects_wrong_root_key() {
    let (_root, _kp, notice) = make_notice();
    let other_root = AuthorityRootKeyPair::generate(&mut OsRng);
    let err = verify_compromise_notice(&other_root.verifying_key_bytes(), &notice)
        .expect_err("wrong root key must be rejected");
    assert!(matches!(
        err,
        KyriotesCsk2Error::AuthorityState("compromise notice signature invalid")
    ));
}

#[test]
fn compromise_notice_rejects_tampered_epoch_pk() {
    let (root, _, mut notice) = make_notice();
    notice.compromised_epoch_pk[0] ^= 0xFF;
    let err = verify_compromise_notice(&root.verifying_key_bytes(), &notice)
        .expect_err("tampered epoch pk must be rejected");
    assert!(matches!(
        err,
        KyriotesCsk2Error::AuthorityState("compromise notice signature invalid")
    ));
}

#[test]
fn compromise_notice_rejects_tampered_compromised_epoch() {
    let (root, _, mut notice) = make_notice();
    notice.compromised_epoch = 99;
    let err = verify_compromise_notice(&root.verifying_key_bytes(), &notice)
        .expect_err("tampered epoch must be rejected");
    assert!(matches!(
        err,
        KyriotesCsk2Error::AuthorityState("compromise notice signature invalid")
    ));
}

#[test]
fn compromise_notice_rejects_tampered_recovery_root() {
    let (root, _, mut notice) = make_notice();
    notice.recovery_authority_root[0] ^= 0xFF;
    let err = verify_compromise_notice(&root.verifying_key_bytes(), &notice)
        .expect_err("tampered recovery root must be rejected");
    assert!(matches!(
        err,
        KyriotesCsk2Error::AuthorityState("compromise notice signature invalid")
    ));
}

// ---------------------------------------------------------------------------
// check_epoch_not_compromised
// ---------------------------------------------------------------------------

#[test]
fn check_epoch_not_compromised_rejects_declared_key_at_declared_epoch() {
    let (root, epoch_kp, _) = make_notice();
    let epoch_pk = epoch_kp.verifying_key_bytes();
    let notice = root.issue_compromise_notice(&epoch_pk, 42, [0u8; 32]);

    let err = check_epoch_not_compromised(42, &epoch_pk, &notice)
        .expect_err("compromised key at declared epoch must be rejected");
    assert!(matches!(
        err,
        KyriotesCsk2Error::AuthorityState("epoch key has been declared compromised")
    ));
}

#[test]
fn check_epoch_not_compromised_rejects_declared_key_at_later_epoch() {
    let (root, epoch_kp, _) = make_notice();
    let epoch_pk = epoch_kp.verifying_key_bytes();
    let notice = root.issue_compromise_notice(&epoch_pk, 42, [0u8; 32]);

    let err = check_epoch_not_compromised(100, &epoch_pk, &notice)
        .expect_err("compromised key at any epoch >= declared epoch must be rejected");
    assert!(matches!(
        err,
        KyriotesCsk2Error::AuthorityState("epoch key has been declared compromised")
    ));
}

#[test]
fn check_epoch_not_compromised_allows_different_epoch_key() {
    let (root, bad_kp, _) = make_notice();
    let good_kp = EpochSigningKeyPair::generate(&mut OsRng);
    let notice = root.issue_compromise_notice(&bad_kp.verifying_key_bytes(), 42, [0u8; 32]);

    check_epoch_not_compromised(42, &good_kp.verifying_key_bytes(), &notice)
        .expect("unrelated epoch key must not be rejected by this notice");
}

#[test]
fn check_epoch_not_compromised_allows_same_key_before_compromise_epoch() {
    let (root, epoch_kp, _) = make_notice();
    let epoch_pk = epoch_kp.verifying_key_bytes();
    let notice = root.issue_compromise_notice(&epoch_pk, 42, [0u8; 32]);

    // Epoch 41 is strictly before the declared compromise boundary.
    check_epoch_not_compromised(41, &epoch_pk, &notice)
        .expect("same key before compromise epoch must be allowed for historical opens");
}
