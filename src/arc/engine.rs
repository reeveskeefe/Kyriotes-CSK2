use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

use crate::core::error::ArcError;
use crate::core::temporal::TemporalPolicy;
use crate::encoding::codec::{put_bytes, put_rights, put_str, put_temporal_policy, put_u64};

use super::async_transparency::AsyncTransparencyLog;
use super::authority::{
    AuthorityRootKeyPair, EpochKeyCert, EpochSigningKeyPair, verify_compromise_notice,
};
use super::capability_tree::{
    AuthorityCapabilityTree, CapabilityIssuanceProof, verify_capability_inclusion,
    verify_capability_issuance, verify_non_revocation,
};
use super::kem::{hybrid_secret, kem_decaps, kem_encaps};
use super::model::{
    ArcObject, AuthorityState, AuthorityWrapper, Capability, CapabilityProof, CompromiseNotice,
    OpenRequest, RecipientPublicKey, RecipientSecretKey, TransparencyProof, capability_leaf_hash,
    capability_stamp, context_hash,
};
use super::transparency::{TransparencyLog, TransparencyStateCommit, transparency_log_entry_hash};
use super::verify::{AuthorityVerifier, BasicAuthorityVerifier, CryptoAuthorityVerifier};
use crate::core::rights::Rights;

/// Maximum allowed delegation depth for a capability chain.
///
/// Prevents integer overflow at issuance and caps chain length to a sane bound.
/// Chains deeper than this are rejected by [`delegate_capability`].
pub const MAX_DELEGATION_DEPTH: u64 = 255;

pub fn validate_capability(
    cap: &Capability,
    proof: &CapabilityProof,
    state: &AuthorityState,
    req: &OpenRequest,
) -> Result<(), ArcError> {
    // Spec §5: delegated capabilities (delegation_depth > 0) must carry a non-zero
    // parent_stamp; directly-issued capabilities must have parent_stamp == [0u8;32].
    if cap.delegation_depth > 0 && cap.parent_stamp == [0u8; 32] {
        return Err(ArcError::InvalidCapability(
            "delegated capability must have non-zero parent_stamp",
        ));
    }
    if cap.delegation_depth == 0 && cap.parent_stamp != [0u8; 32] {
        return Err(ArcError::InvalidCapability(
            "directly-issued capability must have zero parent_stamp",
        ));
    }

    verify_capability_inclusion(cap, &proof.inclusion, &state.authority_root)
        .map_err(|_| ArcError::InvalidCapability("merkle inclusion failed"))?;

    let expected_stamp = capability_stamp(cap, state);
    if proof.non_revocation.stamp != expected_stamp {
        return Err(ArcError::InvalidCapability("capability revoked"));
    }
    verify_non_revocation(
        &proof.non_revocation,
        &state.revocation_root,
        state.revocation_count,
    )
    .map_err(|_| ArcError::InvalidCapability("capability revoked"))?;

    verify_capability_issuance(
        cap,
        &state.authority_root,
        proof.issuance.epoch_cert.epoch,
        &proof.issuance,
        &state.root_pk,
    )
    .map_err(|_| ArcError::InvalidCapability("invalid issuance signature"))?;

    if cap.object_id != req.object_id {
        return Err(ArcError::InvalidCapability("object mismatch"));
    }
    if !cap.rights.contains_all(req.required_rights) {
        return Err(ArcError::InvalidCapability("insufficient rights"));
    }
    if cap.policy_hash != req.policy_hash {
        return Err(ArcError::InvalidCapability("policy hash mismatch"));
    }
    if req.epoch < cap.epoch_start || req.epoch > cap.epoch_end {
        return Err(ArcError::InvalidCapability(
            "epoch outside capability validity",
        ));
    }
    if req.epoch != state.epoch {
        return Err(ArcError::InvalidCapability(
            "request epoch does not match authority state",
        ));
    }
    Ok(())
}

/// Derive a delegated capability from `parent_cap` for a new subject (spec §2, §5).
///
/// # Delegation rules
/// - `parent_cap` must carry [`Rights::DELEGATE`].
/// - `new_rights` must be a subset of `parent_cap.rights` (no rights escalation).
/// - `[new_epoch_start, new_epoch_end]` must be contained within
///   `[parent_cap.epoch_start, parent_cap.epoch_end]` (no epoch window expansion).
/// - The returned capability has `delegation_depth = parent_cap.delegation_depth + 1`
///   and `parent_stamp = capability_stamp(parent_cap, state)`.
///
/// After calling this function the issuing authority must:
/// 1. Add the capability to its [`AuthorityCapabilityTree`] via `add_capability`.
/// 2. Sign it with [`EpochSigningKeyPair::sign_capability_issuance`] to produce a
///    [`CapabilityIssuanceProof`] and deliver both to the delegatee.
pub fn delegate_capability(
    parent_cap: &Capability,
    state: &AuthorityState,
    new_subject: &str,
    new_rights: Rights,
    new_epoch_start: u64,
    new_epoch_end: u64,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Capability, ArcError> {
    if !parent_cap.rights.contains_all(Rights::DELEGATE) {
        return Err(ArcError::InvalidCapability(
            "parent capability does not carry Rights::DELEGATE",
        ));
    }
    if !parent_cap.rights.contains_all(new_rights) {
        return Err(ArcError::InvalidCapability(
            "delegated rights exceed parent capability rights",
        ));
    }
    if new_epoch_start < parent_cap.epoch_start || new_epoch_end > parent_cap.epoch_end {
        return Err(ArcError::InvalidCapability(
            "delegated epoch window exceeds parent capability epoch window",
        ));
    }
    if new_epoch_start > new_epoch_end {
        return Err(ArcError::InvalidCapability(
            "delegated epoch_start exceeds epoch_end",
        ));
    }
    if parent_cap.delegation_depth >= MAX_DELEGATION_DEPTH {
        return Err(ArcError::InvalidCapability(
            "maximum delegation depth exceeded",
        ));
    }
    let parent_stamp = capability_stamp(parent_cap, state);
    let mut nonce = [0u8; 16];
    rng.fill_bytes(&mut nonce);
    Ok(Capability {
        version: parent_cap.version,
        subject: new_subject.to_string(),
        object_id: parent_cap.object_id.clone(),
        rights: new_rights,
        policy_hash: parent_cap.policy_hash,
        epoch_start: new_epoch_start,
        epoch_end: new_epoch_end,
        delegation_depth: parent_cap.delegation_depth + 1,
        parent_stamp,
        nonce,
    })
}

fn authority_digest(state: &AuthorityState, policy_hash: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ARC-AUTHORITY-DIGEST-v1");
    hasher.update(state.authority_root);
    hasher.update(state.revocation_root);
    hasher.update(state.transparency_root);
    hasher.update(state.epoch.to_le_bytes());
    hasher.update(policy_hash);
    hasher.update(state.authority_id.as_bytes());
    hasher.update(state.revocation_count.to_le_bytes());
    hasher.finalize().into()
}

fn derive_kek(
    ss_h: &[u8; 32],
    state: &AuthorityState,
    ctx: [u8; 32],
    policy_hash: [u8; 32],
) -> [u8; 32] {
    let salt = authority_digest(state, policy_hash);
    let hk = Hkdf::<Sha256>::new(Some(&salt), &[ss_h.as_slice(), &ctx].concat());
    let mut out = [0u8; 32];
    let mut info = Vec::with_capacity(10 + ctx.len());
    info.extend_from_slice(b"ARC-KEK-v1");
    info.extend_from_slice(&ctx);
    hk.expand(&info, &mut out)
        .expect("hkdf expand length is fixed and valid");
    out
}

fn wrap_dek(
    kek: [u8; 32],
    nonce: [u8; 12],
    dek: [u8; 32],
    aad: &[u8],
) -> Result<Vec<u8>, ArcError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&kek));
    cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload { msg: &dek, aad },
        )
        .map_err(|_| ArcError::Crypto("failed to wrap DEK"))
}

fn unwrap_dek(
    kek: [u8; 32],
    nonce: [u8; 12],
    wrapped_dek: &[u8],
    aad: &[u8],
) -> Result<[u8; 32], ArcError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&kek));
    let dec = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload {
                msg: wrapped_dek,
                aad,
            },
        )
        .map_err(|_| ArcError::Crypto("failed to unwrap DEK"))?;

    if dec.len() != 32 {
        return Err(ArcError::Crypto("invalid unwrapped DEK length"));
    }

    let mut dek = [0u8; 32];
    dek.copy_from_slice(&dec);
    Ok(dek)
}

fn payload_encrypt(
    dek: [u8; 32],
    nonce: [u8; 12],
    message: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, ArcError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&dek));
    cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload { msg: message, aad },
        )
        .map_err(|_| ArcError::Crypto("payload encryption failed"))
}

fn payload_decrypt(
    dek: [u8; 32],
    nonce: [u8; 12],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, ArcError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&dek));
    cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| ArcError::Crypto("payload decryption failed"))
}

fn authority_aad(
    object: &ArcObject,
    state: &AuthorityState,
    ctx: [u8; 32],
    kem_ct_classical: &[u8; 32],
    kem_ct_pq: &[u8],
) -> Vec<u8> {
    let mut aad = Vec::new();
    // v2: kem_ct_classical added so the AEAD tag on wrapped_dek commits to
    // both KEM ciphertexts.  Omitting it (v1) allowed silent substitution of
    // the classical ephemeral key by any party who knew the DEK (V8 fix).
    aad.extend_from_slice(b"ARC-AUTHORITY-AAD-v2");
    put_str(&mut aad, &object.object_id);
    put_rights(&mut aad, object.required_rights);
    put_bytes(&mut aad, &object.policy_hash);
    put_u64(&mut aad, state.epoch);
    put_bytes(&mut aad, &state.authority_root);
    put_bytes(&mut aad, &state.revocation_root);
    put_bytes(&mut aad, &state.transparency_root);
    put_bytes(&mut aad, &ctx);
    put_temporal_policy(&mut aad, &object.temporal_policy);
    put_bytes(&mut aad, kem_ct_classical);
    put_bytes(&mut aad, kem_ct_pq);
    aad
}

fn payload_aad(object: &ArcObject) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(b"ARC-PAYLOAD-AAD-v1");
    put_str(&mut aad, &object.object_id);
    put_rights(&mut aad, object.required_rights);
    put_bytes(&mut aad, &object.policy_hash);
    put_u64(&mut aad, object.seal_epoch);
    aad
}

fn required_epoch(policy: &TemporalPolicy, e_open: u64, e_seal: u64) -> u64 {
    policy.required_wrapper_epoch(e_open, e_seal)
}

fn select_required_wrapper<'a>(
    object: &'a ArcObject,
    state: &AuthorityState,
) -> Result<(u64, &'a AuthorityWrapper), ArcError> {
    let e_open = state.epoch;
    if !object.temporal_policy.accepts(e_open, object.seal_epoch) {
        return Err(ArcError::TemporalRejected);
    }

    let e_req = required_epoch(&object.temporal_policy, e_open, object.seal_epoch);
    if e_req != state.epoch {
        return Err(ArcError::AuthorityState(
            "open attempted with wrong authority epoch for temporal policy",
        ));
    }

    let wrapper = object
        .wrappers
        .iter()
        .find(|w| w.epoch == e_req)
        .ok_or(ArcError::MissingWrapper)?;

    Ok((e_req, wrapper))
}

fn open_request_for_object(object: &ArcObject, epoch: u64) -> OpenRequest {
    OpenRequest {
        object_id: object.object_id.clone(),
        required_rights: object.required_rights,
        policy_hash: object.policy_hash,
        epoch,
    }
}

// Keep the v0.1 public API stable until request-struct APIs are designed.
#[allow(clippy::too_many_arguments)]
pub fn seal(
    recipient_pk: &RecipientPublicKey,
    message: &[u8],
    cap: &Capability,
    proof: &CapabilityProof,
    transparency_proof: &TransparencyProof,
    state: &AuthorityState,
    req: &OpenRequest,
    temporal_policy: TemporalPolicy,
) -> Result<ArcObject, ArcError> {
    let verifier = BasicAuthorityVerifier;
    seal_with_verifier(
        &verifier,
        recipient_pk,
        message,
        cap,
        proof,
        transparency_proof,
        state,
        req,
        temporal_policy,
    )
}

// Keep the v0.1 public API stable until request-struct APIs are designed.
#[allow(clippy::too_many_arguments)]
pub fn seal_with_verifier<V: AuthorityVerifier>(
    verifier: &V,
    recipient_pk: &RecipientPublicKey,
    message: &[u8],
    cap: &Capability,
    proof: &CapabilityProof,
    transparency_proof: &TransparencyProof,
    state: &AuthorityState,
    req: &OpenRequest,
    temporal_policy: TemporalPolicy,
) -> Result<ArcObject, ArcError> {
    verifier.verify_state(state, transparency_proof)?;
    validate_capability(cap, proof, state, req)?;

    let mut payload_nonce = [0u8; 12];
    let mut wrap_nonce = [0u8; 12];
    let mut dek = [0u8; 32];

    let mut rng = rand::rngs::OsRng;
    rng.fill_bytes(&mut payload_nonce);
    rng.fill_bytes(&mut wrap_nonce);
    rng.fill_bytes(&mut dek);

    let (kem_ct_classical, ss_c, kem_ct_pq, ss_pq) = kem_encaps(recipient_pk, &mut rng);
    let ss_h = hybrid_secret(
        &ss_c,
        if kem_ct_pq.is_empty() {
            None
        } else {
            Some(&ss_pq)
        },
    );

    let cap_stamp = capability_stamp(cap, state);

    let mut object = ArcObject {
        version: 1,
        suite: "ARC-DEV-CHACHA20POLY1305-HKDF-SHA256".to_string(),
        object_id: req.object_id.clone(),
        required_rights: req.required_rights,
        policy_hash: req.policy_hash,
        seal_epoch: state.epoch,
        temporal_policy,
        authority_root: state.authority_root,
        revocation_root: state.revocation_root,
        payload_nonce,
        payload_ciphertext: Vec::new(),
        wrappers: Vec::new(),
    };

    let payload_ct = payload_encrypt(dek, payload_nonce, message, &payload_aad(&object))?;
    object.payload_ciphertext = payload_ct;

    let ctx = context_hash(
        &object.object_id,
        object.required_rights,
        object.policy_hash,
        state,
        cap_stamp,
        &object.temporal_policy,
    );

    let kek = derive_kek(&ss_h, state, ctx, object.policy_hash);
    let aad_auth = authority_aad(&object, state, ctx, &kem_ct_classical, &kem_ct_pq);
    let wrapped_dek = wrap_dek(kek, wrap_nonce, dek, &aad_auth)?;

    object.wrappers.push(AuthorityWrapper {
        epoch: state.epoch,
        kem_ct_classical,
        kem_ct_pq,
        wrap_nonce,
        wrapped_dek,
        context_hash: ctx,
        capability_stamp: cap_stamp,
        transparency_proof: transparency_proof.clone(),
    });

    Ok(object)
}

/// Seal a message and atomically commit the authority state to the transparency
/// log in a single operation.
///
/// This is the single-step variant of calling [`seal_with_verifier`] followed
/// by [`TransparencyLog::commit_state`] manually.  The committed state's real
/// `transparency_root` and [`TransparencyProof`] are baked into the returned
/// [`ArcObject`]'s wrapper, so the object is immediately verifiable against the
/// returned [`TransparencyStateCommit`].
///
/// # Errors
///
/// Returns `Err` if the state cannot be committed, if capability validation
/// fails, or if encryption fails.
// Keep the v0.1 public API stable until request-struct APIs are designed.
#[allow(clippy::too_many_arguments)]
pub fn seal_and_commit<V: AuthorityVerifier, L: TransparencyLog>(
    log: &mut L,
    verifier: &V,
    recipient_pk: &RecipientPublicKey,
    message: &[u8],
    cap: &Capability,
    proof: &CapabilityProof,
    state: &AuthorityState,
    req: &OpenRequest,
    temporal_policy: TemporalPolicy,
) -> Result<(ArcObject, TransparencyStateCommit), ArcError> {
    let commit = log.commit_state(state)?;
    let object = seal_with_verifier(
        verifier,
        recipient_pk,
        message,
        cap,
        proof,
        &commit.proof,
        &commit.state,
        req,
        temporal_policy,
    )?;
    Ok((object, commit))
}

fn unwrap_dek_for_epoch(
    recipient_sk: &RecipientSecretKey,
    object: &ArcObject,
    cap: &Capability,
    state: &AuthorityState,
    wrapper: &AuthorityWrapper,
) -> Result<[u8; 32], ArcError> {
    if wrapper.epoch != state.epoch {
        return Err(ArcError::AuthorityState(
            "selected wrapper epoch does not match authority state epoch",
        ));
    }

    let cap_stamp = capability_stamp(cap, state);
    if cap_stamp != wrapper.capability_stamp {
        return Err(ArcError::InvalidCapability(
            "capability stamp mismatch for wrapper",
        ));
    }

    let ctx = context_hash(
        &object.object_id,
        object.required_rights,
        object.policy_hash,
        state,
        cap_stamp,
        &object.temporal_policy,
    );

    if ctx != wrapper.context_hash {
        return Err(ArcError::AuthorityState("context hash mismatch"));
    }

    let (ss_c, ss_pq) = kem_decaps(recipient_sk, &wrapper.kem_ct_classical, &wrapper.kem_ct_pq);
    let ss_h = hybrid_secret(
        &ss_c,
        if wrapper.kem_ct_pq.is_empty() {
            None
        } else {
            Some(&ss_pq)
        },
    );
    let kek = derive_kek(&ss_h, state, ctx, object.policy_hash);
    let aad = authority_aad(
        object,
        state,
        ctx,
        &wrapper.kem_ct_classical,
        &wrapper.kem_ct_pq,
    );
    unwrap_dek(kek, wrapper.wrap_nonce, &wrapper.wrapped_dek, &aad)
}

pub fn open(
    recipient_sk: &RecipientSecretKey,
    object: &ArcObject,
    cap: &Capability,
    proof: &CapabilityProof,
    state: &AuthorityState,
) -> Result<Vec<u8>, ArcError> {
    let verifier = BasicAuthorityVerifier;
    open_with_verifier(&verifier, recipient_sk, object, cap, proof, state)
}

pub fn open_with_verifier<V: AuthorityVerifier>(
    verifier: &V,
    recipient_sk: &RecipientSecretKey,
    object: &ArcObject,
    cap: &Capability,
    proof: &CapabilityProof,
    state: &AuthorityState,
) -> Result<Vec<u8>, ArcError> {
    let (e_req, wrapper) = select_required_wrapper(object, state)?;

    verifier.verify_state(state, &wrapper.transparency_proof)?;

    let req = open_request_for_object(object, e_req);

    validate_capability(cap, proof, state, &req)?;

    let dek = unwrap_dek_for_epoch(recipient_sk, object, cap, state, wrapper)?;
    payload_decrypt(
        dek,
        object.payload_nonce,
        &object.payload_ciphertext,
        &payload_aad(object),
    )
}

// Keep the v0.1 public API stable until request-struct APIs are designed.
#[allow(clippy::too_many_arguments)]
pub fn add_epoch_wrapper(
    recipient_sk: &RecipientSecretKey,
    recipient_pk: &RecipientPublicKey,
    object: &mut ArcObject,
    cap: &Capability,
    proof: &CapabilityProof,
    from_state: &AuthorityState,
    to_state: &AuthorityState,
    to_transparency_proof: &TransparencyProof,
) -> Result<(), ArcError> {
    let verifier = BasicAuthorityVerifier;
    add_epoch_wrapper_with_verifier(
        &verifier,
        recipient_sk,
        recipient_pk,
        object,
        cap,
        proof,
        from_state,
        to_state,
        to_transparency_proof,
    )
}

// Keep the v0.1 public API stable until request-struct APIs are designed.
#[allow(clippy::too_many_arguments)]
pub fn add_epoch_wrapper_with_verifier<V: AuthorityVerifier>(
    verifier: &V,
    recipient_sk: &RecipientSecretKey,
    recipient_pk: &RecipientPublicKey,
    object: &mut ArcObject,
    cap: &Capability,
    proof: &CapabilityProof,
    from_state: &AuthorityState,
    to_state: &AuthorityState,
    to_transparency_proof: &TransparencyProof,
) -> Result<(), ArcError> {
    let from_wrapper = object
        .wrappers
        .iter()
        .find(|w| w.epoch == from_state.epoch)
        .ok_or(ArcError::MissingWrapper)?;

    verifier.verify_state(from_state, &from_wrapper.transparency_proof)?;
    verifier.verify_state(to_state, to_transparency_proof)?;

    let from_req = OpenRequest {
        object_id: object.object_id.clone(),
        required_rights: object.required_rights,
        policy_hash: object.policy_hash,
        epoch: from_state.epoch,
    };

    validate_capability(cap, proof, from_state, &from_req)?;

    let dek = unwrap_dek_for_epoch(recipient_sk, object, cap, from_state, from_wrapper)?;

    // Spec §15 precondition: A_to.epoch > A_from.epoch.
    if to_state.epoch <= from_state.epoch {
        return Err(ArcError::InvalidCapability(
            "rewrap target epoch must be strictly later than source epoch",
        ));
    }

    // Verify the capability's validity window covers to_state.epoch.
    // (from_state epoch validity is checked inside validate_capability above.)
    if to_state.epoch < cap.epoch_start || to_state.epoch > cap.epoch_end {
        return Err(ArcError::InvalidCapability(
            "epoch outside capability validity",
        ));
    }

    let cap_stamp = capability_stamp(cap, to_state);
    let ctx = context_hash(
        &object.object_id,
        object.required_rights,
        object.policy_hash,
        to_state,
        cap_stamp,
        &object.temporal_policy,
    );

    let mut wrap_nonce = [0u8; 12];
    let mut rng = rand::rngs::OsRng;
    rng.fill_bytes(&mut wrap_nonce);
    let (kem_ct_classical, ss_c, kem_ct_pq, ss_pq) = kem_encaps(recipient_pk, &mut rng);
    let ss_h = hybrid_secret(
        &ss_c,
        if kem_ct_pq.is_empty() {
            None
        } else {
            Some(&ss_pq)
        },
    );
    let kek = derive_kek(&ss_h, to_state, ctx, object.policy_hash);
    let aad = authority_aad(object, to_state, ctx, &kem_ct_classical, &kem_ct_pq);

    let wrapped_dek = wrap_dek(kek, wrap_nonce, dek, &aad)?;

    if let Some(existing) = object
        .wrappers
        .iter_mut()
        .find(|w| w.epoch == to_state.epoch)
    {
        *existing = AuthorityWrapper {
            epoch: to_state.epoch,
            kem_ct_classical,
            kem_ct_pq,
            wrap_nonce,
            wrapped_dek,
            context_hash: ctx,
            capability_stamp: cap_stamp,
            transparency_proof: to_transparency_proof.clone(),
        };
        return Ok(());
    }

    object.wrappers.push(AuthorityWrapper {
        epoch: to_state.epoch,
        kem_ct_classical,
        kem_ct_pq,
        wrap_nonce,
        wrapped_dek,
        context_hash: ctx,
        capability_stamp: cap_stamp,
        transparency_proof: to_transparency_proof.clone(),
    });

    Ok(())
}

/// Commit `to_state` to the transparency log then add an epoch re-wrap wrapper
/// to `object` in a single atomic step.
///
/// Combines [`TransparencyLog::commit_state`] with
/// [`add_epoch_wrapper_with_verifier`] so callers get a consistent
/// `TransparencyStateCommit` whose proof is baked into the wrapper.
// Keep the v0.1 public API stable until request-struct APIs are designed.
#[allow(clippy::too_many_arguments)]
pub fn add_epoch_wrapper_and_commit<V: AuthorityVerifier, L: TransparencyLog>(
    log: &mut L,
    verifier: &V,
    recipient_sk: &RecipientSecretKey,
    recipient_pk: &RecipientPublicKey,
    object: &mut ArcObject,
    cap: &Capability,
    proof: &CapabilityProof,
    from_state: &AuthorityState,
    to_state: &AuthorityState,
) -> Result<TransparencyStateCommit, ArcError> {
    let commit = log.commit_state(to_state)?;
    add_epoch_wrapper_with_verifier(
        verifier,
        recipient_sk,
        recipient_pk,
        object,
        cap,
        proof,
        from_state,
        &commit.state,
        &commit.proof,
    )?;
    Ok(commit)
}

/// Revoke a capability in the authority tree and produce the next authority state.
///
/// This helper enforces state/tree root consistency before mutation, computes the
/// revocation stamp for `revoke_epoch`, updates the tree, and returns a new state
/// ready to commit to transparency.
pub fn revoke_capability(
    tree: &mut AuthorityCapabilityTree,
    cap: &Capability,
    base_state: &AuthorityState,
    revoke_epoch: u64,
) -> Result<AuthorityState, ArcError> {
    if tree.inclusion_proof(cap).is_none() {
        return Err(ArcError::InvalidCapability(
            "capability not found in authority tree",
        ));
    }

    if tree.authority_root() != base_state.authority_root {
        return Err(ArcError::AuthorityState(
            "authority root does not match capability tree",
        ));
    }

    if tree.revocation_root() != base_state.revocation_root {
        return Err(ArcError::AuthorityState(
            "revocation root does not match capability tree",
        ));
    }

    if revoke_epoch <= base_state.epoch {
        return Err(ArcError::AuthorityState(
            "revocation epoch must be greater than base authority epoch",
        ));
    }

    let mut revoked_state = base_state.clone();
    revoked_state.epoch = revoke_epoch;
    revoked_state.transparency_root = [0u8; 32];

    tree.revoke_capability(cap, &revoked_state);
    revoked_state.authority_root = tree.authority_root();
    revoked_state.revocation_root = tree.revocation_root();
    revoked_state.revocation_count = tree.revocation_count();

    Ok(revoked_state)
}

/// Revoke a capability and commit the resulting authority state into transparency.
///
/// Returns the committed state (with updated transparency root) and its inclusion
/// proof from the transparency backend.
pub fn revoke_capability_and_commit<L: TransparencyLog>(
    log: &mut L,
    tree: &mut AuthorityCapabilityTree,
    cap: &Capability,
    base_state: &AuthorityState,
    revoke_epoch: u64,
) -> Result<TransparencyStateCommit, ArcError> {
    let revoked_state = revoke_capability(tree, cap, base_state, revoke_epoch)?;
    log.commit_state(&revoked_state)
}

/// Async variant of [`revoke_capability_and_commit`] for network-backed logs.
///
/// Accepts `&mut dyn AsyncTransparencyLog` so it works with both concrete
/// types and `Box<dyn AsyncTransparencyLog>`.
pub async fn revoke_capability_and_commit_async(
    log: &mut dyn AsyncTransparencyLog,
    tree: &mut AuthorityCapabilityTree,
    cap: &Capability,
    base_state: &AuthorityState,
    revoke_epoch: u64,
) -> Result<TransparencyStateCommit, ArcError> {
    let revoked_state = revoke_capability(tree, cap, base_state, revoke_epoch)?;
    log.commit_state(&revoked_state).await
}

/// Public verifiability check for an ARC object — spec §2 Verify.
///
/// Validates the authority certificate chain, temporal policy, and capability
/// predicate without attempting DEK unwrapping or payload decryption.  Useful
/// for pre-flight checks and for verifiers that do not hold `sk_B`.
pub fn verify(
    object: &ArcObject,
    cap: &Capability,
    proof: &CapabilityProof,
    state: &AuthorityState,
    transparency_proof: &TransparencyProof,
) -> Result<(), ArcError> {
    let verifier = BasicAuthorityVerifier;
    verify_with_verifier(&verifier, object, cap, proof, state, transparency_proof)
}

/// Verify variant that accepts a custom [`AuthorityVerifier`].
///
/// Steps (per spec §2 Verify):
/// 1. Verify epoch certificate chain and epoch root signature (via `verifier`).
/// 2. Check `TemporalAccept`.
/// 3. Select required wrapper epoch `e_req`.
/// 4. Run `ValidCap` checks (§9).
pub fn verify_with_verifier<V: AuthorityVerifier>(
    verifier: &V,
    object: &ArcObject,
    cap: &Capability,
    proof: &CapabilityProof,
    state: &AuthorityState,
    transparency_proof: &TransparencyProof,
) -> Result<(), ArcError> {
    // Step 1: epoch chain + transparency inclusion.
    verifier.verify_state(state, transparency_proof)?;

    // Step 2: temporal policy acceptance.
    let e_open = state.epoch;
    if !object.temporal_policy.accepts(e_open, object.seal_epoch) {
        return Err(ArcError::TemporalRejected);
    }

    // Step 3: select required wrapper epoch; the supplied state must match.
    let e_req = required_epoch(&object.temporal_policy, e_open, object.seal_epoch);
    if e_req != state.epoch {
        return Err(ArcError::AuthorityState(
            "verify called with wrong authority epoch for temporal policy",
        ));
    }

    // Step 4: ValidCap (§9) — no decryption.
    let req = OpenRequest {
        object_id: object.object_id.clone(),
        required_rights: object.required_rights,
        policy_hash: object.policy_hash,
        epoch: e_req,
    };
    validate_capability(cap, proof, state, &req)
}

/// Reseal an ARC object with a fresh DEK and (optionally) a new recipient key
/// or new authority state — spec §15 Reseal.
///
/// This is the combined Open + Reseal operation: it decrypts the existing
/// payload using `recipient_sk` / `open_state`, then immediately reseals it
/// under `recipient_pk_new` / `seal_state` with a freshly sampled DEK.
///
/// `open_proof` must be valid for `open_state`; `seal_proof` must be valid
/// for `seal_state`.  When resealing within the same authority epoch the
/// same proof may be supplied for both arguments.
// Keep the v0.1 public API stable until request-struct APIs are designed.
#[allow(clippy::too_many_arguments)]
pub fn open_and_reseal(
    recipient_sk: &RecipientSecretKey,
    recipient_pk_new: &RecipientPublicKey,
    object: &ArcObject,
    cap: &Capability,
    open_proof: &CapabilityProof,
    open_state: &AuthorityState,
    seal_proof: &CapabilityProof,
    seal_transparency_proof: &TransparencyProof,
    seal_state: &AuthorityState,
    seal_req: &OpenRequest,
    new_temporal_policy: TemporalPolicy,
) -> Result<ArcObject, ArcError> {
    let verifier = BasicAuthorityVerifier;
    open_and_reseal_with_verifier(
        &verifier,
        recipient_sk,
        recipient_pk_new,
        object,
        cap,
        open_proof,
        open_state,
        seal_proof,
        seal_transparency_proof,
        seal_state,
        seal_req,
        new_temporal_policy,
    )
}

/// Reseal variant that accepts a custom [`AuthorityVerifier`].
// Keep the v0.1 public API stable until request-struct APIs are designed.
#[allow(clippy::too_many_arguments)]
pub fn open_and_reseal_with_verifier<V: AuthorityVerifier>(
    verifier: &V,
    recipient_sk: &RecipientSecretKey,
    recipient_pk_new: &RecipientPublicKey,
    object: &ArcObject,
    cap: &Capability,
    open_proof: &CapabilityProof,
    open_state: &AuthorityState,
    seal_proof: &CapabilityProof,
    seal_transparency_proof: &TransparencyProof,
    seal_state: &AuthorityState,
    seal_req: &OpenRequest,
    new_temporal_policy: TemporalPolicy,
) -> Result<ArcObject, ArcError> {
    // Step 1: Open the existing object to recover M.
    let plaintext =
        open_with_verifier(verifier, recipient_sk, object, cap, open_proof, open_state)?;

    // Step 2–4: Seal M under the new state with a fresh DEK (spec §15 Reseal).
    seal_with_verifier(
        verifier,
        recipient_pk_new,
        &plaintext,
        cap,
        seal_proof,
        seal_transparency_proof,
        seal_state,
        seal_req,
        new_temporal_policy,
    )
}

/// Reseal an ARC object and atomically commit the new seal state to the
/// transparency log — spec §15 Reseal.
///
/// Combines [`open_and_reseal_with_verifier`] with a transparency commit so
/// callers receive a sealed object whose wrapper is bound to the committed
/// (real) `transparency_root`.  Useful when the seal state has not yet been
/// committed, e.g. after `rotate_epoch` without a prior `commit_state`.
///
/// The `open_state` must already be committed (so `open_with_verifier` can
/// find a valid wrapper).  The `seal_state` is committed by this function.
// Keep the v0.1 public API stable until request-struct APIs are designed.
#[allow(clippy::too_many_arguments)]
pub fn open_and_reseal_and_commit<V: AuthorityVerifier, L: TransparencyLog>(
    log: &mut L,
    verifier: &V,
    recipient_sk: &RecipientSecretKey,
    recipient_pk_new: &RecipientPublicKey,
    object: &ArcObject,
    cap: &Capability,
    open_proof: &CapabilityProof,
    open_state: &AuthorityState,
    seal_proof: &CapabilityProof,
    seal_state: &AuthorityState,
    seal_req: &OpenRequest,
    new_temporal_policy: TemporalPolicy,
) -> Result<(ArcObject, TransparencyStateCommit), ArcError> {
    let seal_commit = log.commit_state(seal_state)?;
    let new_object = open_and_reseal_with_verifier(
        verifier,
        recipient_sk,
        recipient_pk_new,
        object,
        cap,
        open_proof,
        open_state,
        seal_proof,
        &seal_commit.proof,
        &seal_commit.state,
        seal_req,
        new_temporal_policy,
    )?;
    Ok((new_object, seal_commit))
}

/// Check that `epoch_pk` has not been declared compromised for `epoch`.
///
/// Returns `Err` when `epoch_pk == notice.compromised_epoch_pk` and
/// `epoch >= notice.compromised_epoch`.  Historical opens at epochs
/// strictly earlier than the declared compromise boundary are still allowed.
///
/// Callers are responsible for verifying the notice signature with
/// `verify_compromise_notice` before relying on this check.
pub fn check_epoch_not_compromised(
    epoch: u64,
    epoch_pk: &[u8; 32],
    notice: &CompromiseNotice,
) -> Result<(), ArcError> {
    if epoch_pk == &notice.compromised_epoch_pk && epoch >= notice.compromised_epoch {
        return Err(ArcError::AuthorityState(
            "epoch key has been declared compromised",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Capability issuance (spec §2 Issue)
// ---------------------------------------------------------------------------

/// Issue a capability into the authority tree and produce an authenticated
/// issuance proof — spec §2 Issue.
///
/// The capability is added to `tree` (idempotent: adding the same cap twice
/// leaves the root unchanged).  The returned [`CapabilityIssuanceProof`] binds
/// `cap` to the authority root **after** the addition under `epoch_cert.epoch`.
///
/// Callers must subsequently commit the updated `AuthorityState` to
/// transparency (using [`issue_capability_and_commit`] or by calling
/// `log.commit_state` manually) so the new root is publicly observable.
///
/// # Errors
///
/// Returns `Err` if `epoch_cert.epoch` is outside `[cap.epoch_start,
/// cap.epoch_end]`, which would cause subsequent `verify_capability_issuance`
/// calls to reject the proof.
pub fn issue_capability(
    tree: &mut AuthorityCapabilityTree,
    cap: &Capability,
    epoch_kp: &EpochSigningKeyPair,
    epoch_cert: &EpochKeyCert,
) -> Result<CapabilityIssuanceProof, ArcError> {
    if epoch_cert.epoch < cap.epoch_start || epoch_cert.epoch > cap.epoch_end {
        return Err(ArcError::InvalidCapability(
            "epoch cert epoch is outside capability validity range",
        ));
    }

    tree.add_capability(cap);

    let leaf_hash = capability_leaf_hash(cap);
    let sig =
        epoch_kp.sign_capability_issuance(&leaf_hash, &tree.authority_root(), epoch_cert.epoch);

    Ok(CapabilityIssuanceProof {
        sig,
        epoch_cert: epoch_cert.clone(),
    })
}

/// Issue a capability and atomically commit the resulting authority state to
/// the transparency log.
///
/// This is the recommended end-to-end authority operation: after this call the
/// new authority root (reflecting the added capability) is committed and the
/// returned [`TransparencyStateCommit`] carries the transparency proof needed
/// by recipients to open objects sealed against this state.
///
/// `base_state` must be consistent with `tree` (same `authority_root`,
/// `revocation_root`, and `revocation_count`).
pub fn issue_capability_and_commit<L: TransparencyLog>(
    log: &mut L,
    tree: &mut AuthorityCapabilityTree,
    cap: &Capability,
    epoch_kp: &EpochSigningKeyPair,
    epoch_cert: &EpochKeyCert,
    base_state: &AuthorityState,
) -> Result<(CapabilityIssuanceProof, TransparencyStateCommit), ArcError> {
    if tree.authority_root() != base_state.authority_root {
        return Err(ArcError::AuthorityState(
            "authority root does not match capability tree before issuance",
        ));
    }
    if tree.revocation_root() != base_state.revocation_root {
        return Err(ArcError::AuthorityState(
            "revocation root does not match capability tree before issuance",
        ));
    }

    let proof = issue_capability(tree, cap, epoch_kp, epoch_cert)?;

    // Build the new state reflecting the post-issuance authority root.
    let mut new_state = base_state.clone();
    new_state.authority_root = tree.authority_root();
    new_state.transparency_root = [0u8; 32]; // will be set by commit_state

    let commit = log.commit_state(&new_state)?;
    Ok((proof, commit))
}

// ---------------------------------------------------------------------------
// Compromise-aware open / verify (spec §16 enforcement)
// ---------------------------------------------------------------------------

/// Open an ARC object while enforcing one or more [`CompromiseNotice`]s.
///
/// Implements spec §16 "Enforcement flow (integrated into the Open predicate)":
/// for each notice, the signature is verified under `state.root_pk` and the
/// epoch key used for sealing is checked against the declared compromise
/// boundary.  The open is rejected if the sealing epoch key has been
/// compromised.
///
/// `notices` may be empty — the call degrades to a plain [`open`] in that
/// case.
pub fn open_with_compromise_check(
    recipient_sk: &RecipientSecretKey,
    object: &ArcObject,
    cap: &Capability,
    proof: &CapabilityProof,
    state: &AuthorityState,
    notices: &[CompromiseNotice],
) -> Result<Vec<u8>, ArcError> {
    let verifier = BasicAuthorityVerifier;
    open_with_compromise_check_and_verifier(
        &verifier,
        recipient_sk,
        object,
        cap,
        proof,
        state,
        notices,
    )
}

/// Compromise-aware open that accepts a custom [`AuthorityVerifier`].
pub fn open_with_compromise_check_and_verifier<V: AuthorityVerifier>(
    verifier: &V,
    recipient_sk: &RecipientSecretKey,
    object: &ArcObject,
    cap: &Capability,
    proof: &CapabilityProof,
    state: &AuthorityState,
    notices: &[CompromiseNotice],
) -> Result<Vec<u8>, ArcError> {
    enforce_compromise_notices(state, &proof.issuance.epoch_cert.epoch_pk, notices)?;
    open_with_verifier(verifier, recipient_sk, object, cap, proof, state)
}

/// Verify an ARC object while enforcing one or more [`CompromiseNotice`]s.
///
/// Mirrors [`open_with_compromise_check`] but performs the public-verifier
/// path (no `sk_B` needed) — spec §2 Verify + §16.
pub fn verify_with_compromise_check(
    object: &ArcObject,
    cap: &Capability,
    proof: &CapabilityProof,
    state: &AuthorityState,
    transparency_proof: &TransparencyProof,
    notices: &[CompromiseNotice],
) -> Result<(), ArcError> {
    let verifier = BasicAuthorityVerifier;
    verify_with_compromise_check_and_verifier(
        &verifier,
        object,
        cap,
        proof,
        state,
        transparency_proof,
        notices,
    )
}

/// Compromise-aware verify that accepts a custom [`AuthorityVerifier`].
pub fn verify_with_compromise_check_and_verifier<V: AuthorityVerifier>(
    verifier: &V,
    object: &ArcObject,
    cap: &Capability,
    proof: &CapabilityProof,
    state: &AuthorityState,
    transparency_proof: &TransparencyProof,
    notices: &[CompromiseNotice],
) -> Result<(), ArcError> {
    enforce_compromise_notices(state, &proof.issuance.epoch_cert.epoch_pk, notices)?;
    verify_with_verifier(verifier, object, cap, proof, state, transparency_proof)
}

/// Internal helper: verify each notice signature under `state.root_pk` and
/// check the epoch key used for the capability's issuance proof.
///
/// Steps per spec §16:
/// 1. Verify each notice signature under `state.root_pk`.
/// 2. Run `CheckCompromise(e_open, pk_A_e, notice)` — reject if compromised,
///    where `e_open = state.epoch` is the current open/verify epoch.
fn enforce_compromise_notices(
    state: &AuthorityState,
    seal_epoch_pk: &[u8; 32],
    notices: &[CompromiseNotice],
) -> Result<(), ArcError> {
    for notice in notices {
        // Step 1: authenticate the notice under the offline root key.
        verify_compromise_notice(&state.root_pk, notice)?;

        // Step 2: reject if the sealing epoch key is declared compromised at or
        // before the current open epoch (spec §16 CheckCompromise(e_open, pk_A_e)).
        check_epoch_not_compromised(state.epoch, seal_epoch_pk, notice)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Epoch rotation (spec §7 — advance to a fresh epoch signing key)
// ---------------------------------------------------------------------------

/// Rotate to a new epoch by generating a fresh [`EpochSigningKeyPair`] and
/// issuing a new [`EpochKeyCert`] under the offline root key.
///
/// The returned [`AuthorityState`] seed has `epoch = new_epoch`, preserves
/// the `authority_root`, `revocation_root`, `root_pk`, `authority_id`, and
/// `revocation_count` from `base_state`, and sets `transparency_root` to
/// zeros (ready to be filled by [`TransparencyLog::commit_state`]).
///
/// Use [`rotate_epoch_and_commit`] to atomically commit the new epoch state
/// to a transparency log in a single call.
pub(crate) fn rotated_authority_state(
    base_state: &AuthorityState,
    new_epoch: u64,
    prev_epoch_hash: &[u8; 32],
) -> AuthorityState {
    AuthorityState {
        authority_root: base_state.authority_root,
        revocation_root: base_state.revocation_root,
        transparency_root: [0u8; 32],
        epoch: new_epoch,
        authority_id: base_state.authority_id.clone(),
        epoch_signature_valid: true,
        epoch_key_cert_valid: true,
        transparency_inclusion_valid: true,
        root_pk: base_state.root_pk,
        revocation_count: base_state.revocation_count,
        prev_epoch_hash: *prev_epoch_hash,
    }
}

pub fn rotate_epoch(
    root_kp: &AuthorityRootKeyPair,
    base_state: &AuthorityState,
    new_epoch: u64,
    validity_window: u64,
    prev_epoch_hash: &[u8; 32],
) -> (EpochSigningKeyPair, EpochKeyCert, AuthorityState) {
    let epoch_kp = EpochSigningKeyPair::generate(&mut rand::rngs::OsRng);
    let epoch_cert =
        root_kp.issue_epoch_cert(&epoch_kp.verifying_key_bytes(), new_epoch, validity_window);
    let new_state = rotated_authority_state(base_state, new_epoch, prev_epoch_hash);
    (epoch_kp, epoch_cert, new_state)
}

/// Rotate to a new epoch and atomically commit the new state to the
/// transparency log.
///
/// Combines [`rotate_epoch`] with a [`TransparencyLog::commit_state`] call so
/// callers get a single, consistent `(EpochSigningKeyPair, EpochKeyCert,
/// TransparencyStateCommit)` ready for sealing and verification.
///
/// # Errors
///
/// Returns `Err` if the transparency log rejects the commit (e.g. conflicting
/// state for the same `(authority_id, epoch)`).
pub fn rotate_epoch_and_commit<L: TransparencyLog>(
    log: &mut L,
    root_kp: &AuthorityRootKeyPair,
    base_state: &AuthorityState,
    new_epoch: u64,
    validity_window: u64,
    prev_epoch_hash: &[u8; 32],
) -> Result<(EpochSigningKeyPair, EpochKeyCert, TransparencyStateCommit), ArcError> {
    let (epoch_kp, epoch_cert, new_state) = rotate_epoch(
        root_kp,
        base_state,
        new_epoch,
        validity_window,
        prev_epoch_hash,
    );
    let mut commit = log.commit_state(&new_state)?;

    // Sign sigma_e with the real transparency_root now that T_e is known.
    let sigma_e = epoch_kp.sign_epoch_root(
        &commit.state.authority_root,
        &commit.state.revocation_root,
        &commit.state.transparency_root,
        new_epoch,
        prev_epoch_hash,
    );

    // Compute Log_e = transparency_log_entry_hash(Log_{e-1}, R_e, Rev_e, e, pk_A_e, sigma_e)
    // and register it in the log so it can be used as prev_epoch_hash for the next rotation.
    let chain_hash = transparency_log_entry_hash(
        prev_epoch_hash,
        &commit.state.authority_root,
        &commit.state.revocation_root,
        commit.state.epoch,
        &epoch_kp.verifying_key_bytes(),
        &sigma_e,
    );
    commit.chain_hash = chain_hash;
    log.store_chain_hash(&commit.state.authority_id, commit.state.epoch, chain_hash);

    Ok((epoch_kp, epoch_cert, commit))
}

/// Bundled result of a full epoch rotation.
///
/// Contains every output needed to immediately start sealing and verifying
/// under the new epoch — including `sigma_e`, which is required to populate
/// a [`CryptoAuthorityVerifier`] but is not returned by
/// [`rotate_epoch_and_commit`].
///
/// Obtain via [`rotate_epoch_full`].
pub struct EpochRotation {
    /// Fresh epoch online signing keypair.  Keep this secret.
    pub epoch_kp: EpochSigningKeyPair,
    /// Epoch key certificate issued by the offline root.
    pub epoch_cert: EpochKeyCert,
    /// Epoch online public key (32-byte Ed25519 verifying key).
    pub epoch_pk: [u8; 32],
    /// Epoch root signature: `Sign(sk_A_e, "ARC-EPOCH-ROOT-v2" || …)` (§7).
    pub sigma_e: [u8; 64],
    /// Committed authority state with real `transparency_root`.
    pub state: AuthorityState,
    /// Transparency inclusion proof for `state`.
    pub transparency_proof: TransparencyProof,
    /// Chain hash for this epoch — pass as `prev_epoch_hash` for the next
    /// call to [`rotate_epoch_full`] or [`rotate_epoch_and_commit`].
    pub chain_hash: [u8; 32],
}

impl EpochRotation {
    /// Build a [`CryptoAuthorityVerifier`] with this epoch's evidence
    /// pre-registered and ready for use.
    ///
    /// The returned verifier can be passed directly to
    /// [`seal_with_verifier`], [`open_with_verifier`], or
    /// [`verify_with_verifier`] without any further setup.
    pub fn into_verifier(&self) -> CryptoAuthorityVerifier {
        let mut v = CryptoAuthorityVerifier::with_root_pk(self.state.root_pk);
        v.add_evidence(
            &self.state.authority_id,
            self.state.epoch,
            self.epoch_pk,
            self.sigma_e,
            self.epoch_cert.clone(),
        );
        v
    }
}

/// Rotate to a new epoch and receive all outputs bundled in an [`EpochRotation`].
///
/// This is the ergonomic single-call alternative to [`rotate_epoch_and_commit`].
/// In addition to generating the fresh epoch keypair, issuing the cert, signing
/// the epoch root, and committing to the transparency log, it also surfaces
/// `sigma_e` and pre-computes `epoch_pk` — the two pieces that
/// [`rotate_epoch_and_commit`] discards and that are required to populate a
/// [`CryptoAuthorityVerifier`].
///
/// Typical usage:
///
/// ```ignore
/// let rot = rotate_epoch_full(&mut log, &root_kp, &base_state, 2, 100, &prev_hash)?;
/// let verifier = rot.into_verifier(); // CryptoAuthorityVerifier, ready to use
/// let obj = seal_with_verifier(&verifier, &pk_b, msg, &cap, &proof,
///                              &rot.transparency_proof, &rot.state, &req, policy)?;
/// ```
///
/// # Errors
///
/// Returns `Err` if the transparency log rejects the commit.
pub(crate) fn begin_epoch_rotation_commit<L: TransparencyLog>(
    log: &mut L,
    new_state: &AuthorityState,
) -> Result<TransparencyStateCommit, ArcError> {
    log.commit_state(new_state)
}

pub(crate) fn finalize_epoch_rotation_commit<L: TransparencyLog>(
    log: &mut L,
    epoch_kp: EpochSigningKeyPair,
    epoch_cert: EpochKeyCert,
    new_state: &AuthorityState,
    new_epoch: u64,
    prev_epoch_hash: &[u8; 32],
) -> Result<EpochRotation, ArcError> {
    let mut commit = begin_epoch_rotation_commit(log, new_state)?;
    let epoch_pk = epoch_kp.verifying_key_bytes();

    let sigma_e = epoch_kp.sign_epoch_root(
        &commit.state.authority_root,
        &commit.state.revocation_root,
        &commit.state.transparency_root,
        new_epoch,
        prev_epoch_hash,
    );

    let chain_hash = transparency_log_entry_hash(
        prev_epoch_hash,
        &commit.state.authority_root,
        &commit.state.revocation_root,
        commit.state.epoch,
        &epoch_pk,
        &sigma_e,
    );

    commit.chain_hash = chain_hash;
    log.store_chain_hash(&commit.state.authority_id, commit.state.epoch, chain_hash);

    Ok(EpochRotation {
        epoch_kp,
        epoch_cert,
        epoch_pk,
        sigma_e,
        state: commit.state,
        transparency_proof: commit.proof,
        chain_hash,
    })
}

pub fn rotate_epoch_full<L: TransparencyLog>(
    log: &mut L,
    root_kp: &AuthorityRootKeyPair,
    base_state: &AuthorityState,
    new_epoch: u64,
    validity_window: u64,
    prev_epoch_hash: &[u8; 32],
) -> Result<EpochRotation, ArcError> {
    let (epoch_kp, epoch_cert, new_state) = rotate_epoch(
        root_kp,
        base_state,
        new_epoch,
        validity_window,
        prev_epoch_hash,
    );

    finalize_epoch_rotation_commit(
        log,
        epoch_kp,
        epoch_cert,
        &new_state,
        new_epoch,
        prev_epoch_hash,
    )
}
