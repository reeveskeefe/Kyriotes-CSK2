//! Epoch-scoped authority key certificate chain (spec §7).
//!
//! ARC separates the long-lived offline authority root key from the per-epoch
//! online signing key:
//!
//! ```text
//! cert_e = Sign(sk_A_off, H("ARC-EPOCH-KEY-v1" || pk_A_e || e || validity_window))
//! sigma_e = Sign(sk_A_e,  H("ARC-EPOCH-ROOT-v1" || R_e || Rev_e || e || prev_epoch_hash))
//! ```
//!
//! A verifier with `pk_A_off` can authenticate any `pk_A_e` via `cert_e`, then
//! verify the epoch root signature under the authenticated `pk_A_e`.
//! Leaking `sk_A_e` only compromises epoch `e`, not historical epochs.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::{CryptoRng, RngCore};

use crate::core::error::ArcError;
use super::model::CompromiseNotice;

// ---------------------------------------------------------------------------
// Core cert type
// ---------------------------------------------------------------------------

/// Certificate that binds an epoch online public key to the offline authority
/// root, per spec §7.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochKeyCert {
    /// Ed25519 public key of the epoch online signer (`pk_A_e`).
    pub epoch_pk: [u8; 32],
    /// Epoch number this certificate authorises.
    pub epoch: u64,
    /// Number of epochs the online key is considered valid (informational).
    pub validity_window: u64,
    /// Offline root's signature over `epoch_cert_signing_message(...)`.
    pub signature: [u8; 64],
}

// ---------------------------------------------------------------------------
// Canonical signing messages
// ---------------------------------------------------------------------------

/// Canonical message signed by the offline root to produce an `EpochKeyCert`.
///
/// Format: `"ARC-EPOCH-KEY-v1" || pk_A_e || epoch_le64 || validity_window_le64`
pub fn epoch_cert_signing_message(
    epoch_pk: &[u8; 32],
    epoch: u64,
    validity_window: u64,
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(16 + 32 + 8 + 8);
    msg.extend_from_slice(b"ARC-EPOCH-KEY-v1");
    msg.extend_from_slice(epoch_pk);
    msg.extend_from_slice(&epoch.to_le_bytes());
    msg.extend_from_slice(&validity_window.to_le_bytes());
    msg
}

/// Canonical message the epoch online key signs when issuing a capability.
///
/// Format: `"ARC-CAPABILITY-ISSUE-v1" || leaf_hash || authority_root || epoch_le64`
///
/// `leaf_hash` is `capability_leaf_hash(cap)` from `arc::model`.
pub fn capability_issuance_signing_message(
    leaf_hash: &[u8; 32],
    authority_root: &[u8; 32],
    epoch: u64,
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(22 + 32 + 32 + 8);
    msg.extend_from_slice(b"ARC-CAPABILITY-ISSUE-v1");
    msg.extend_from_slice(leaf_hash);
    msg.extend_from_slice(authority_root);
    msg.extend_from_slice(&epoch.to_le_bytes());
    msg
}

/// Canonical message signed by the epoch online key to commit authority roots.
///
/// Format: `"ARC-EPOCH-ROOT-v1" || R_e || Rev_e || epoch_le64 || prev_epoch_hash`
///
/// Use `[0u8; 32]` for `prev_epoch_hash` at the genesis epoch.
pub fn epoch_root_signing_message(
    authority_root: &[u8; 32],
    revocation_root: &[u8; 32],
    epoch: u64,
    prev_epoch_hash: &[u8; 32],
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(17 + 32 + 32 + 8 + 32);
    msg.extend_from_slice(b"ARC-EPOCH-ROOT-v1");
    msg.extend_from_slice(authority_root);
    msg.extend_from_slice(revocation_root);
    msg.extend_from_slice(&epoch.to_le_bytes());
    msg.extend_from_slice(prev_epoch_hash);
    msg
}

/// Canonical message signed by the offline authority root to produce a `CompromiseNotice`.
///
/// Format: `"ARC-COMPROMISE-v1" || pk_A_e_bad || e_bad_le64 || R_recover`
pub fn compromise_notice_signing_message(
    compromised_epoch_pk: &[u8; 32],
    compromised_epoch: u64,
    recovery_authority_root: &[u8; 32],
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(17 + 32 + 8 + 32);
    msg.extend_from_slice(b"ARC-COMPROMISE-v1");
    msg.extend_from_slice(compromised_epoch_pk);
    msg.extend_from_slice(&compromised_epoch.to_le_bytes());
    msg.extend_from_slice(recovery_authority_root);
    msg
}

// ---------------------------------------------------------------------------
// Verification helpers
// ---------------------------------------------------------------------------

/// Verify that `cert` was signed by the offline authority root whose public key
/// is `root_pk_bytes`.
pub fn verify_epoch_cert(
    root_pk_bytes: &[u8; 32],
    cert: &EpochKeyCert,
) -> Result<(), ArcError> {
    let root_pk = VerifyingKey::from_bytes(root_pk_bytes)
        .map_err(|_| ArcError::AuthorityState("invalid authority root public key"))?;
    let msg = epoch_cert_signing_message(&cert.epoch_pk, cert.epoch, cert.validity_window);
    let sig = Signature::from_bytes(&cert.signature);
    root_pk
        .verify_strict(&msg, &sig)
        .map_err(|_| ArcError::AuthorityState("epoch key certificate signature invalid"))
}

/// Verify the epoch root signature produced by the authenticated epoch online key.
///
/// Call `verify_epoch_cert` first to authenticate `epoch_pk_bytes`.
///
/// `prev_epoch_hash` is `[0u8; 32]` for the genesis epoch.
pub fn verify_epoch_root_sig(
    epoch_pk_bytes: &[u8; 32],
    authority_root: &[u8; 32],
    revocation_root: &[u8; 32],
    epoch: u64,
    prev_epoch_hash: &[u8; 32],
    sig_bytes: &[u8; 64],
) -> Result<(), ArcError> {
    let epoch_pk = VerifyingKey::from_bytes(epoch_pk_bytes)
        .map_err(|_| ArcError::AuthorityState("invalid epoch public key"))?;
    let msg =
        epoch_root_signing_message(authority_root, revocation_root, epoch, prev_epoch_hash);
    let sig = Signature::from_bytes(sig_bytes);
    epoch_pk
        .verify_strict(&msg, &sig)
        .map_err(|_| ArcError::AuthorityState("epoch root signature invalid"))
}

/// Verify that `notice` was signed by the offline authority root whose public
/// key is `root_pk_bytes`.
pub fn verify_compromise_notice(
    root_pk_bytes: &[u8; 32],
    notice: &CompromiseNotice,
) -> Result<(), ArcError> {
    let root_pk = VerifyingKey::from_bytes(root_pk_bytes)
        .map_err(|_| ArcError::AuthorityState("invalid authority root public key"))?;
    let msg = compromise_notice_signing_message(
        &notice.compromised_epoch_pk,
        notice.compromised_epoch,
        &notice.recovery_authority_root,
    );
    let sig = Signature::from_bytes(&notice.signature);
    root_pk
        .verify_strict(&msg, &sig)
        .map_err(|_| ArcError::AuthorityState("compromise notice signature invalid"))
}

// ---------------------------------------------------------------------------
// Key pair types
// ---------------------------------------------------------------------------

/// The offline authority root keypair.
///
/// In production this key lives air-gapped; in tests it is generated fresh per
/// scenario.  Only the verifying key needs to be distributed to verifiers.
pub struct AuthorityRootKeyPair {
    signing_key: SigningKey,
}

impl AuthorityRootKeyPair {
    /// Generate a fresh keypair using `rng`.
    pub fn generate(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self {
            signing_key: SigningKey::from_bytes(&bytes),
        }
    }

    /// Reconstruct a keypair deterministically from a 32-byte seed (test use only).
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&seed),
        }
    }

    /// The offline root verifying (public) key, distributed to all verifiers.
    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Issue an `EpochKeyCert` that certifies `epoch_pk` for the given `epoch`
    /// and `validity_window`.
    pub fn issue_epoch_cert(
        &self,
        epoch_pk: &[u8; 32],
        epoch: u64,
        validity_window: u64,
    ) -> EpochKeyCert {
        let msg = epoch_cert_signing_message(epoch_pk, epoch, validity_window);
        let signature = self.signing_key.sign(&msg).to_bytes();
        EpochKeyCert {
            epoch_pk: *epoch_pk,
            epoch,
            validity_window,
            signature,
        }
    }

    /// Issue a `CompromiseNotice` declaring that `compromised_epoch_pk` (the
    /// epoch online key used at `compromised_epoch`) is no longer trustworthy.
    ///
    /// `recovery_authority_root` is the authority root from which clients
    /// should resume trust (typically the root at `compromised_epoch + 1`).
    pub fn issue_compromise_notice(
        &self,
        compromised_epoch_pk: &[u8; 32],
        compromised_epoch: u64,
        recovery_authority_root: [u8; 32],
    ) -> CompromiseNotice {
        let msg = compromise_notice_signing_message(
            compromised_epoch_pk,
            compromised_epoch,
            &recovery_authority_root,
        );
        let signature = self.signing_key.sign(&msg).to_bytes();
        CompromiseNotice {
            compromised_epoch_pk: *compromised_epoch_pk,
            compromised_epoch,
            recovery_authority_root,
            signature,
        }
    }
}

/// An epoch-scoped online signing keypair.
///
/// One keypair per epoch; the matching public key is certified by the offline
/// authority root via `EpochKeyCert`.
pub struct EpochSigningKeyPair {
    signing_key: SigningKey,
}

impl EpochSigningKeyPair {
    /// Generate a fresh keypair using `rng`.
    pub fn generate(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self {
            signing_key: SigningKey::from_bytes(&bytes),
        }
    }

    /// Reconstruct a keypair deterministically from a 32-byte seed (test use only).
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&seed),
        }
    }

    /// The epoch verifying (public) key.
    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Produce the epoch root signature over `(authority_root, revocation_root,
    /// epoch, prev_epoch_hash)`.
    ///
    /// `prev_epoch_hash` is `[0u8; 32]` for the genesis epoch.
    pub fn sign_epoch_root(
        &self,
        authority_root: &[u8; 32],
        revocation_root: &[u8; 32],
        epoch: u64,
        prev_epoch_hash: &[u8; 32],
    ) -> [u8; 64] {
        let msg =
            epoch_root_signing_message(authority_root, revocation_root, epoch, prev_epoch_hash);
        self.signing_key.sign(&msg).to_bytes()
    }

    /// Issue a capability by signing its leaf hash under this epoch's authority.
    ///
    /// The returned 64-byte signature is the `sig` field of a
    /// `CapabilityIssuanceProof`.  The caller must also supply the matching
    /// `EpochKeyCert` (issued by the offline root) when constructing the proof.
    pub fn sign_capability_issuance(
        &self,
        leaf_hash: &[u8; 32],
        authority_root: &[u8; 32],
        epoch: u64,
    ) -> [u8; 64] {
        let msg = capability_issuance_signing_message(leaf_hash, authority_root, epoch);
        self.signing_key.sign(&msg).to_bytes()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn make_keypairs() -> (AuthorityRootKeyPair, EpochSigningKeyPair) {
        (
            AuthorityRootKeyPair::generate(&mut OsRng),
            EpochSigningKeyPair::generate(&mut OsRng),
        )
    }

    #[test]
    fn verify_epoch_cert_accepts_valid_cert() {
        let (root, epoch_kp) = make_keypairs();
        let cert = root.issue_epoch_cert(&epoch_kp.verifying_key_bytes(), 5, 10);
        verify_epoch_cert(&root.verifying_key_bytes(), &cert)
            .expect("valid cert should verify");
    }

    #[test]
    fn verify_epoch_cert_rejects_tampered_epoch_number() {
        let (root, epoch_kp) = make_keypairs();
        let mut cert = root.issue_epoch_cert(&epoch_kp.verifying_key_bytes(), 5, 10);
        cert.epoch = 99; // tamper
        let err = verify_epoch_cert(&root.verifying_key_bytes(), &cert)
            .expect_err("tampered epoch should be rejected");
        assert!(matches!(
            err,
            ArcError::AuthorityState("epoch key certificate signature invalid")
        ));
    }

    #[test]
    fn verify_epoch_cert_rejects_wrong_root_key() {
        let (root, epoch_kp) = make_keypairs();
        let (other_root, _) = make_keypairs();
        let cert = root.issue_epoch_cert(&epoch_kp.verifying_key_bytes(), 5, 10);
        let err = verify_epoch_cert(&other_root.verifying_key_bytes(), &cert)
            .expect_err("cert signed by a different root must be rejected");
        assert!(matches!(
            err,
            ArcError::AuthorityState("epoch key certificate signature invalid")
        ));
    }

    #[test]
    fn verify_epoch_root_sig_accepts_valid_sig() {
        let (root, epoch_kp) = make_keypairs();
        let cert = root.issue_epoch_cert(&epoch_kp.verifying_key_bytes(), 7, 10);
        let r_e = [1u8; 32];
        let rev_e = [2u8; 32];
        let sig = epoch_kp.sign_epoch_root(&r_e, &rev_e, 7, &[0u8; 32]);
        verify_epoch_root_sig(&cert.epoch_pk, &r_e, &rev_e, 7, &[0u8; 32], &sig)
            .expect("valid epoch root sig should verify");
    }

    #[test]
    fn verify_epoch_root_sig_rejects_tampered_authority_root() {
        let (_, epoch_kp) = make_keypairs();
        let r_e = [1u8; 32];
        let rev_e = [2u8; 32];
        let sig = epoch_kp.sign_epoch_root(&r_e, &rev_e, 7, &[0u8; 32]);
        let mut tampered_r = r_e;
        tampered_r[0] ^= 0xFF;
        let err = verify_epoch_root_sig(
            &epoch_kp.verifying_key_bytes(),
            &tampered_r,
            &rev_e,
            7,
            &[0u8; 32],
            &sig,
        )
        .expect_err("tampered authority root must be rejected");
        assert!(matches!(
            err,
            ArcError::AuthorityState("epoch root signature invalid")
        ));
    }

    #[test]
    fn from_seed_is_deterministic() {
        let seed = [42u8; 32];
        let kp1 = AuthorityRootKeyPair::from_seed(seed);
        let kp2 = AuthorityRootKeyPair::from_seed(seed);
        assert_eq!(kp1.verifying_key_bytes(), kp2.verifying_key_bytes());
    }
}
