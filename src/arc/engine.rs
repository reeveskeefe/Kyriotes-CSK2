use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::core::error::ArcError;
use crate::core::temporal::TemporalPolicy;
use crate::encoding::codec::{put_bytes, put_rights, put_str, put_temporal_policy, put_u64};

use super::kem::{hybrid_secret, kem_decaps, kem_encaps};
use super::model::{
    ArcObject,
    AuthorityState,
    AuthorityWrapper,
    Capability,
    CapabilityProof,
    OpenRequest,
    RecipientPublicKey,
    RecipientSecretKey,
    TransparencyProof,
    capability_stamp,
    context_hash,
};
use super::verify::{AuthorityVerifier, BasicAuthorityVerifier};

pub fn validate_capability(
    cap: &Capability,
    proof: &CapabilityProof,
    state: &AuthorityState,
    req: &OpenRequest,
) -> Result<(), ArcError> {
    if !proof.inclusion_valid {
        return Err(ArcError::InvalidCapability("merkle inclusion failed"));
    }
    if !proof.non_revoked {
        return Err(ArcError::InvalidCapability("capability revoked"));
    }
    if !proof.issued_signature_valid {
        return Err(ArcError::InvalidCapability("invalid issuance signature"));
    }
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
        return Err(ArcError::InvalidCapability("epoch outside capability validity"));
    }
    if req.epoch != state.epoch {
        return Err(ArcError::InvalidCapability("request epoch does not match authority state"));
    }
    Ok(())
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
    hasher.finalize().into()
}

fn derive_kek(ss_h: &[u8; 32], state: &AuthorityState, ctx: [u8; 32], policy_hash: [u8; 32]) -> [u8; 32] {
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

fn wrap_dek(kek: [u8; 32], nonce: [u8; 12], dek: [u8; 32], aad: &[u8]) -> Result<Vec<u8>, ArcError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&kek));
    cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload {
                msg: &dek,
                aad,
            },
        )
        .map_err(|_| ArcError::Crypto("failed to wrap DEK"))
}

fn unwrap_dek(kek: [u8; 32], nonce: [u8; 12], wrapped_dek: &[u8], aad: &[u8]) -> Result<[u8; 32], ArcError> {
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

fn payload_encrypt(dek: [u8; 32], nonce: [u8; 12], message: &[u8], aad: &[u8]) -> Result<Vec<u8>, ArcError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&dek));
    cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload { msg: message, aad },
        )
        .map_err(|_| ArcError::Crypto("payload encryption failed"))
}

fn payload_decrypt(dek: [u8; 32], nonce: [u8; 12], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, ArcError> {
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

fn authority_aad(object: &ArcObject, state: &AuthorityState, ctx: [u8; 32]) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(b"ARC-AUTHORITY-AAD-v1");
    put_str(&mut aad, &object.object_id);
    put_rights(&mut aad, object.required_rights);
    put_bytes(&mut aad, &object.policy_hash);
    put_u64(&mut aad, state.epoch);
    put_bytes(&mut aad, &state.authority_root);
    put_bytes(&mut aad, &state.revocation_root);
    put_bytes(&mut aad, &state.transparency_root);
    put_bytes(&mut aad, &ctx);
    put_temporal_policy(&mut aad, &object.temporal_policy);
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

    let (kem_ct_classical, ss_c) = kem_encaps(recipient_pk, &mut rng);
    let kem_ct_pq = [0u8; 32]; // Phase 2: ML-KEM
    let ss_h = hybrid_secret(&ss_c);

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
    let aad_auth = authority_aad(&object, state, ctx);
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

    let ss_c = kem_decaps(recipient_sk, &wrapper.kem_ct_classical);
    let ss_h = hybrid_secret(&ss_c);
    let kek = derive_kek(&ss_h, state, ctx, object.policy_hash);
    let aad = authority_aad(object, state, ctx);
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

    verifier.verify_state(state, &wrapper.transparency_proof)?;

    let req = OpenRequest {
        object_id: object.object_id.clone(),
        required_rights: object.required_rights,
        policy_hash: object.policy_hash,
        epoch: e_req,
    };

    validate_capability(cap, proof, state, &req)?;

    let dek = unwrap_dek_for_epoch(recipient_sk, object, cap, state, wrapper)?;
    payload_decrypt(dek, object.payload_nonce, &object.payload_ciphertext, &payload_aad(object))
}

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

    let to_req = OpenRequest {
        object_id: object.object_id.clone(),
        required_rights: object.required_rights,
        policy_hash: object.policy_hash,
        epoch: to_state.epoch,
    };

    validate_capability(cap, proof, to_state, &to_req)?;

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
    let (kem_ct_classical, ss_c) = kem_encaps(recipient_pk, &mut rng);
    let kem_ct_pq = [0u8; 32]; // Phase 2: ML-KEM
    let ss_h = hybrid_secret(&ss_c);
    let kek = derive_kek(&ss_h, to_state, ctx, object.policy_hash);
    let aad = authority_aad(object, to_state, ctx);

    let wrapped_dek = wrap_dek(kek, wrap_nonce, dek, &aad)?;

    if let Some(existing) = object.wrappers.iter_mut().find(|w| w.epoch == to_state.epoch) {
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

