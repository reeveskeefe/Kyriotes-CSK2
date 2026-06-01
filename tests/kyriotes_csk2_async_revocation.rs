mod helpers;

use helpers::scenario::Scenario;
use kyriotes_csk2::{
    AsyncTransparencyLog, AuthorityCapabilityTree, InMemoryTransparencyLog, KyriotesCsk2Error,
    capability_stamp, revoke_capability_and_commit_async,
};

#[tokio::test]
async fn async_revoke_and_commit_updates_roots_and_log() {
    let s = Scenario::baseline("strict", 42);

    let mut tree = AuthorityCapabilityTree::new();
    tree.add_capability(&s.cap);

    let mut log = InMemoryTransparencyLog::new();
    log.commit_state(&s.seal_state)
        .await
        .expect("base state commit");

    let commit = revoke_capability_and_commit_async(&mut log, &mut tree, &s.cap, &s.seal_state, 43)
        .await
        .expect("async revocation commit should succeed");

    assert_eq!(commit.state.epoch, 43);
    assert_eq!(commit.state.authority_root, s.seal_state.authority_root);
    assert_ne!(commit.state.revocation_root, s.seal_state.revocation_root);

    let revoked_stamp = capability_stamp(&s.cap, &commit.state);
    assert!(tree.is_revoked(&revoked_stamp));
}

#[tokio::test]
async fn async_revoke_and_commit_via_boxed_dyn_log() {
    let s = Scenario::baseline("strict", 42);

    let mut tree = AuthorityCapabilityTree::new();
    tree.add_capability(&s.cap);

    let mut log: Box<dyn AsyncTransparencyLog> = Box::new(InMemoryTransparencyLog::new());
    log.commit_state(&s.seal_state)
        .await
        .expect("base state commit");

    let commit =
        revoke_capability_and_commit_async(log.as_mut(), &mut tree, &s.cap, &s.seal_state, 43)
            .await
            .expect("async revocation via boxed dyn log should succeed");

    assert_eq!(commit.state.epoch, 43);
    assert_ne!(commit.state.revocation_root, s.seal_state.revocation_root);
}

#[tokio::test]
async fn async_revoke_rejects_stale_epoch() {
    let s = Scenario::baseline("strict", 42);

    let mut tree = AuthorityCapabilityTree::new();
    tree.add_capability(&s.cap);

    let mut log = InMemoryTransparencyLog::new();

    // revoke_epoch equal to base epoch (not strictly greater) must be rejected.
    let err = revoke_capability_and_commit_async(&mut log, &mut tree, &s.cap, &s.seal_state, 42)
        .await
        .expect_err("stale revocation epoch must be rejected");

    assert!(matches!(
        err,
        KyriotesCsk2Error::AuthorityState(
            "revocation epoch must be greater than base authority epoch"
        )
    ));
}
