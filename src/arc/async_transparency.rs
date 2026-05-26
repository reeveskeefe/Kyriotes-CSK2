use async_trait::async_trait;

use crate::core::error::ArcError;

use super::model::{AuthorityState, TransparencyProof};
use super::transparency::{InMemoryTransparencyLog, TransparencyLog, TransparencyStateCommit};

/// An async variant of [`TransparencyLog`] for network-backed append-only log
/// services (e.g. Rekor, Certificate Transparency).
///
/// The trait is object-safe: `Box<dyn AsyncTransparencyLog>` works out of the
/// box. Implement it by issuing whatever HTTP / RPC call your log service
/// requires and awaiting the response.
///
/// [`InMemoryTransparencyLog`] implements this trait by simply delegating to the
/// synchronous [`TransparencyLog`] methods, so you can use it in tests without
/// spinning up a runtime-aware backend.
#[async_trait]
pub trait AsyncTransparencyLog: Send {
    /// Commit `state` to the log and return the state with its
    /// `transparency_root` set plus the Merkle inclusion proof.
    async fn commit_state(
        &mut self,
        state: &AuthorityState,
    ) -> Result<TransparencyStateCommit, ArcError>;

    /// Retrieve the Merkle inclusion proof for a previously committed state.
    async fn proof_for_state(
        &self,
        state: &AuthorityState,
    ) -> Result<TransparencyProof, ArcError>;

    /// Return the current Merkle root of the log.
    async fn current_root(&self) -> [u8; 32];
}

/// Blanket async wrapper for any type that already implements [`TransparencyLog`].
///
/// This lets `InMemoryTransparencyLog` (and any future sync implementation) work
/// with callers that hold `&mut dyn AsyncTransparencyLog` without any extra
/// boilerplate.
#[async_trait]
impl AsyncTransparencyLog for InMemoryTransparencyLog {
    async fn commit_state(
        &mut self,
        state: &AuthorityState,
    ) -> Result<TransparencyStateCommit, ArcError> {
        TransparencyLog::commit_state(self, state)
    }

    async fn proof_for_state(
        &self,
        state: &AuthorityState,
    ) -> Result<TransparencyProof, ArcError> {
        TransparencyLog::proof_for_state(self, state)
    }

    async fn current_root(&self) -> [u8; 32] {
        TransparencyLog::current_root(self)
    }
}
