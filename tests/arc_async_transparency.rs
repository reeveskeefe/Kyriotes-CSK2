mod helpers;

use arc_core::{AsyncTransparencyLog, InMemoryTransparencyLog};
use helpers::state::sample_state;

/// Verify that InMemoryTransparencyLog works through the async trait interface.
#[tokio::test]
async fn async_commit_and_proof_roundtrip() {
    let mut log = InMemoryTransparencyLog::new();
    let state = sample_state(1);

    let commit = log.commit_state(&state).await.expect("commit should succeed");

    // The committed state must have a non-zero transparency root.
    assert_ne!(commit.state.transparency_root, [0u8; 32]);

    // current_root must match the root baked into the committed state.
    let root = log.current_root().await;
    assert_eq!(root, commit.state.transparency_root);

    // proof_for_state must reproduce the same proof.
    let proof = log
        .proof_for_state(&commit.state)
        .await
        .expect("proof lookup should succeed");
    assert_eq!(proof.leaf_hash, commit.proof.leaf_hash);
    assert_eq!(proof.leaf_index, commit.proof.leaf_index);
}

/// Verify that a boxed dyn AsyncTransparencyLog works end-to-end,
/// proving the trait is object-safe.
#[tokio::test]
async fn async_trait_is_object_safe_via_boxed_dyn() {
    let mut log: Box<dyn AsyncTransparencyLog> =
        Box::new(InMemoryTransparencyLog::new());

    let state = sample_state(7);
    let commit = log.commit_state(&state).await.expect("commit via dyn should succeed");

    let root = log.current_root().await;
    assert_eq!(root, commit.state.transparency_root);
}

/// Verify that duplicate-epoch protection works through the async path.
#[tokio::test]
async fn async_commit_rejects_conflicting_epoch() {
    let mut log = InMemoryTransparencyLog::new();
    let state_a = sample_state(3);

    log.commit_state(&state_a).await.expect("first commit should succeed");

    // A different state for the same authority_id + epoch must be rejected.
    let mut state_b = sample_state(3);
    state_b.authority_root = [0xffu8; 32]; // mutate to create a different leaf hash

    let err = log
        .commit_state(&state_b)
        .await
        .expect_err("conflicting state should be rejected");

    assert!(
        err.to_string().contains("different state"),
        "unexpected error message: {err}"
    );
}
