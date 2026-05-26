use crate::core::error::ArcError;
use crate::encoding::codec::{put_bytes, put_str, put_u64};

use ed25519_dalek::{Signature, VerifyingKey};

use super::authority::{EpochKeyCert, verify_epoch_cert, verify_epoch_root_sig};
use super::model::{AuthorityState, TransparencyProof, transparency_leaf_hash};
use super::transparency::hash_transparency_node;

pub trait AuthorityVerifier {
    fn verify_state(
        &self,
        state: &AuthorityState,
        transparency_proof: &TransparencyProof,
    ) -> Result<(), ArcError>;
}

#[derive(Default)]
pub struct BasicAuthorityVerifier;

impl AuthorityVerifier for BasicAuthorityVerifier {
    fn verify_state(
        &self,
        state: &AuthorityState,
        _transparency_proof: &TransparencyProof,
    ) -> Result<(), ArcError> {
        if !state.epoch_signature_valid {
            return Err(ArcError::AuthorityState("invalid epoch signature"));
        }
        if !state.epoch_key_cert_valid {
            return Err(ArcError::AuthorityState("invalid epoch key certificate"));
        }
        if !state.transparency_inclusion_valid {
            return Err(ArcError::AuthorityState("missing or invalid transparency proof"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct AuthorityEpochEvidence {
    pub authority_id: String,
    pub epoch: u64,
    /// Epoch online public key (`pk_A_e`).
    pub epoch_pk: [u8; 32],
    /// Epoch root signature over `epoch_root_signing_message(...)` produced by
    /// `sk_A_e`.  In legacy mode (no root pk configured) this is a signature
    /// over `authority_state_signing_message(...)` instead.
    pub epoch_root_sig: [u8; 64],
    /// Certificate from the offline root binding `epoch_pk` to this epoch.
    pub epoch_cert: EpochKeyCert,
}

#[derive(Clone, Debug, Default)]
pub struct AuthorityEvidenceRegistry {
    entries: Vec<AuthorityEpochEvidence>,
}

impl AuthorityEvidenceRegistry {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn add(&mut self, evidence: AuthorityEpochEvidence) {
        if let Some(existing) = self
            .entries
            .iter_mut()
            .find(|e| e.authority_id == evidence.authority_id && e.epoch == evidence.epoch)
        {
            *existing = evidence;
            return;
        }
        self.entries.push(evidence);
    }

    fn find(&self, authority_id: &str, epoch: u64) -> Option<&AuthorityEpochEvidence> {
        self.entries
            .iter()
            .find(|e| e.authority_id == authority_id && e.epoch == epoch)
    }
}

#[derive(Clone, Debug, Default)]
pub struct CryptoAuthorityVerifier {
    evidence_registry: AuthorityEvidenceRegistry,
    enforce_stub_checks: bool,
    /// When set, full cert chain verification is enforced: the epoch key cert
    /// must be signed by this offline root public key, and the epoch root
    /// signature must be signed by the certified epoch key.
    root_pk: Option<[u8; 32]>,
}

impl CryptoAuthorityVerifier {
    /// Create a verifier that uses the legacy signature path (no offline root
    /// anchoring).  Existing callers that do not yet supply a cert chain will
    /// continue to work.
    pub fn new() -> Self {
        Self {
            evidence_registry: AuthorityEvidenceRegistry::new(),
            enforce_stub_checks: true,
            root_pk: None,
        }
    }

    /// Create a verifier that enforces the full `sk_A_off → pk_A_e → sigma_e`
    /// certificate chain per spec §7.
    pub fn with_root_pk(root_pk: [u8; 32]) -> Self {
        Self {
            evidence_registry: AuthorityEvidenceRegistry::new(),
            enforce_stub_checks: true,
            root_pk: Some(root_pk),
        }
    }

    pub fn with_stub_checks(mut self, enforce: bool) -> Self {
        self.enforce_stub_checks = enforce;
        self
    }

    /// Register evidence for `(authority_id, epoch)`.
    ///
    /// - `epoch_pk`      — epoch online public key (`pk_A_e`)
    /// - `epoch_root_sig`— signature over the epoch root message produced by
    ///                     `sk_A_e` (use [`EpochSigningKeyPair::sign_epoch_root`])
    /// - `epoch_cert`    — certificate issued by the offline root binding
    ///                     `epoch_pk` to `epoch` (use
    ///                     [`AuthorityRootKeyPair::issue_epoch_cert`])
    pub fn add_evidence(
        &mut self,
        authority_id: impl Into<String>,
        epoch: u64,
        epoch_pk: [u8; 32],
        epoch_root_sig: [u8; 64],
        epoch_cert: EpochKeyCert,
    ) {
        self.evidence_registry.add(AuthorityEpochEvidence {
            authority_id: authority_id.into(),
            epoch,
            epoch_pk,
            epoch_root_sig,
            epoch_cert,
        });
    }
}

impl AuthorityVerifier for CryptoAuthorityVerifier {
    fn verify_state(
        &self,
        state: &AuthorityState,
        transparency_proof: &TransparencyProof,
    ) -> Result<(), ArcError> {
        if self.enforce_stub_checks {
            if !state.epoch_signature_valid {
                return Err(ArcError::AuthorityState("invalid epoch signature"));
            }
            if !state.epoch_key_cert_valid {
                return Err(ArcError::AuthorityState("invalid epoch key certificate"));
            }
            if !state.transparency_inclusion_valid {
                return Err(ArcError::AuthorityState("missing or invalid transparency proof"));
            }
        }

        let evidence = self
            .evidence_registry
            .find(&state.authority_id, state.epoch)
            .ok_or(ArcError::AuthorityState(
                "missing authority key/signature evidence for epoch",
            ))?;

        match &self.root_pk {
            Some(root_pk) => {
                // Full chain: offline root → epoch cert → epoch root signature.
                verify_epoch_cert(root_pk, &evidence.epoch_cert)?;
                verify_epoch_root_sig(
                    &evidence.epoch_cert.epoch_pk,
                    &state.authority_root,
                    &state.revocation_root,
                    state.epoch,
                    &[0u8; 32], // genesis prev_epoch_hash (chain not yet tracked)
                    &evidence.epoch_root_sig,
                )?;
            }
            None => {
                // Legacy path: verify epoch_root_sig over authority_state_signing_message.
                let key = VerifyingKey::from_bytes(&evidence.epoch_pk)
                    .map_err(|_| ArcError::AuthorityState("invalid authority public key"))?;
                let sig = Signature::from_bytes(&evidence.epoch_root_sig);
                let msg = authority_state_signing_message(state);
                key.verify_strict(&msg, &sig)
                    .map_err(|_| ArcError::AuthorityState("invalid authority signature"))?;
            }
        }

        verify_transparency_inclusion(state, transparency_proof)
    }
}

fn verify_transparency_inclusion(
    state: &AuthorityState,
    proof: &TransparencyProof,
) -> Result<(), ArcError> {
    if !state.transparency_inclusion_valid {
        return Err(ArcError::AuthorityState("missing or invalid transparency proof"));
    }

    let expected_leaf = transparency_leaf_hash(state);
    if proof.leaf_hash != expected_leaf {
        return Err(ArcError::AuthorityState(
            "transparency proof leaf does not match authority state",
        ));
    }

    let mut idx = proof.leaf_index;
    let mut acc = proof.leaf_hash;
    for sibling in &proof.sibling_hashes {
        acc = if idx & 1 == 0 {
            hash_transparency_node(acc, *sibling)
        } else {
            hash_transparency_node(*sibling, acc)
        };
        idx >>= 1;
    }

    if acc != state.transparency_root {
        return Err(ArcError::AuthorityState(
            "transparency proof root mismatch",
        ));
    }

    Ok(())
}

pub fn authority_state_signing_message(state: &AuthorityState) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"ARC-AUTHORITY-STATE-SIG-v1");
    put_bytes(&mut msg, &state.authority_root);
    put_bytes(&mut msg, &state.revocation_root);
    put_bytes(&mut msg, &state.transparency_root);
    put_u64(&mut msg, state.epoch);
    put_str(&mut msg, &state.authority_id);
    msg
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn sample_state() -> AuthorityState {
        let mut state = AuthorityState {
            authority_root: [1u8; 32],
            revocation_root: [2u8; 32],
            transparency_root: [0u8; 32],
            epoch: 42,
            authority_id: "auth-main".to_string(),
            epoch_signature_valid: true,
            epoch_key_cert_valid: true,
            transparency_inclusion_valid: true,
        };
        state.transparency_root = transparency_leaf_hash(&state);
        state
    }

    fn sample_transparency_proof(state: &AuthorityState) -> TransparencyProof {
        TransparencyProof {
            leaf_hash: transparency_leaf_hash(state),
            sibling_hashes: vec![],
            leaf_index: 0,
        }
    }

    // -----------------------------------------------------------------------
    // Helpers shared by legacy-path and cert-chain tests
    // -----------------------------------------------------------------------

    /// Build a dummy `EpochKeyCert` — the signature bytes are all zeros and
    /// will be ignored in the legacy path (no root pk configured).
    fn dummy_cert() -> EpochKeyCert {
        use super::super::authority::EpochKeyCert;
        EpochKeyCert {
            epoch_pk: [0u8; 32],
            epoch: 0,
            validity_window: 0,
            signature: [0u8; 64],
        }
    }

    // -----------------------------------------------------------------------
    // Legacy-path tests (CryptoAuthorityVerifier::new, no root pk)
    // -----------------------------------------------------------------------

    #[test]
    fn crypto_verifier_accepts_valid_signature() {
        let state = sample_state();
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let msg = authority_state_signing_message(&state);
        let sig = signing_key.sign(&msg).to_bytes();

        let mut verifier = CryptoAuthorityVerifier::new();
        verifier.add_evidence(
            state.authority_id.clone(),
            state.epoch,
            signing_key.verifying_key().to_bytes(),
            sig,
            dummy_cert(),
        );

        verifier
            .verify_state(&state, &sample_transparency_proof(&state))
            .expect("signature should verify");
    }

    #[test]
    fn crypto_verifier_rejects_tampered_state() {
        let mut state = sample_state();
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let msg = authority_state_signing_message(&state);
        let sig = signing_key.sign(&msg).to_bytes();

        let mut verifier = CryptoAuthorityVerifier::new();
        verifier.add_evidence(
            state.authority_id.clone(),
            state.epoch,
            signing_key.verifying_key().to_bytes(),
            sig,
            dummy_cert(),
        );

        state.authority_root[0] ^= 0xAA;
        state.transparency_root = transparency_leaf_hash(&state);
        let err = verifier
            .verify_state(&state, &sample_transparency_proof(&state))
            .expect_err("tampered state should fail signature");
        assert!(matches!(err, ArcError::AuthorityState("invalid authority signature")));
    }

    #[test]
    fn crypto_verifier_rejects_missing_evidence() {
        let state = sample_state();
        let verifier = CryptoAuthorityVerifier::new();
        let proof = sample_transparency_proof(&state);
        let err = verifier
            .verify_state(&state, &proof)
            .expect_err("missing evidence should fail");
        assert!(matches!(
            err,
            ArcError::AuthorityState("missing authority key/signature evidence for epoch")
        ));
    }

    #[test]
    fn crypto_verifier_rejects_wrong_transparency_root() {
        let mut state = sample_state();
        state.transparency_root[0] ^= 0xFF;

        let signing_key = SigningKey::from_bytes(&[5u8; 32]);
        let msg = authority_state_signing_message(&state);
        let sig = signing_key.sign(&msg).to_bytes();

        let mut verifier = CryptoAuthorityVerifier::new();
        verifier.add_evidence(
            state.authority_id.clone(),
            state.epoch,
            signing_key.verifying_key().to_bytes(),
            sig,
            dummy_cert(),
        );

        let proof = sample_transparency_proof(&state);
        let err = verifier
            .verify_state(&state, &proof)
            .expect_err("wrong transparency root should fail");
        assert!(matches!(
            err,
            ArcError::AuthorityState("transparency proof root mismatch")
        ));
    }

    // -----------------------------------------------------------------------
    // Full cert-chain tests (CryptoAuthorityVerifier::with_root_pk)
    // -----------------------------------------------------------------------

    fn cert_chain_verifier_for(state: &AuthorityState, root_seed: u8, epoch_seed: u8)
        -> CryptoAuthorityVerifier
    {
        use super::super::authority::{AuthorityRootKeyPair, EpochSigningKeyPair};
        let root_kp = AuthorityRootKeyPair::from_seed([root_seed; 32]);
        let epoch_kp = EpochSigningKeyPair::from_seed([epoch_seed; 32]);
        let epoch_pk = epoch_kp.verifying_key_bytes();
        let cert = root_kp.issue_epoch_cert(&epoch_pk, state.epoch, 10);
        let epoch_root_sig = epoch_kp.sign_epoch_root(
            &state.authority_root,
            &state.revocation_root,
            state.epoch,
            &[0u8; 32],
        );
        let mut verifier = CryptoAuthorityVerifier::with_root_pk(root_kp.verifying_key_bytes());
        verifier.add_evidence(
            state.authority_id.clone(),
            state.epoch,
            epoch_pk,
            epoch_root_sig,
            cert,
        );
        verifier
    }

    #[test]
    fn cert_chain_verifier_accepts_valid_chain() {
        let state = sample_state();
        let verifier = cert_chain_verifier_for(&state, 1, 2);
        verifier
            .verify_state(&state, &sample_transparency_proof(&state))
            .expect("full cert chain should verify");
    }

    #[test]
    fn cert_chain_verifier_rejects_tampered_authority_root() {
        let original = sample_state();
        let verifier = cert_chain_verifier_for(&original, 3, 4);

        // Authority root in the presented state differs from what was signed.
        let mut tampered = original.clone();
        tampered.authority_root[0] ^= 0xFF;
        tampered.transparency_root = transparency_leaf_hash(&tampered);

        let err = verifier
            .verify_state(&tampered, &sample_transparency_proof(&tampered))
            .expect_err("tampered authority root must be rejected");
        assert!(matches!(
            err,
            ArcError::AuthorityState("epoch root signature invalid")
        ));
    }

    #[test]
    fn cert_chain_verifier_rejects_wrong_root_pk() {
        let state = sample_state();
        // Verifier built with a different root key than what signed the cert.
        let verifier = cert_chain_verifier_for(&state, 5, 6);

        // Swap in a second verifier's root pk, leaving evidence from the first.
        use super::super::authority::AuthorityRootKeyPair;
        let wrong_root_pk = AuthorityRootKeyPair::from_seed([99u8; 32]).verifying_key_bytes();
        let mut bad_verifier = CryptoAuthorityVerifier::with_root_pk(wrong_root_pk);
        // Copy evidence from the correct verifier into the bad one.
        for ev in &verifier.evidence_registry.entries {
            bad_verifier.add_evidence(
                ev.authority_id.clone(),
                ev.epoch,
                ev.epoch_pk,
                ev.epoch_root_sig,
                ev.epoch_cert.clone(),
            );
        }

        let err = bad_verifier
            .verify_state(&state, &sample_transparency_proof(&state))
            .expect_err("wrong root pk must be rejected");
        assert!(matches!(
            err,
            ArcError::AuthorityState("epoch key certificate signature invalid")
        ));
    }
}
