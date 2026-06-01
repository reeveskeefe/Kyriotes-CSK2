use crate::KyriotesCsk2Error;
use crate::encoding::codec::{
    put_bytes, put_rights, put_str, put_temporal_policy, put_u16, put_u32, put_u64,
    take_bytes_limited, take_fixed_limited, take_rights, take_str_limited, take_temporal_policy,
    take_u16, take_u32, take_u64,
};
use crate::kyriotes_csk2::model::{
    AuthorityWrapper, Capability, KyriotesCsk2Object, TransparencyProof,
};
use crate::kyriotes_csk2::tsig::{ThresholdPartialSig, ThresholdSignatureSet};

const MAGIC: &[u8; 4] = b"KCS2";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodeLimits {
    pub max_suite_len: usize,
    pub max_object_id_len: usize,
    pub max_payload_ciphertext_len: usize,
    pub max_wrappers: usize,
    pub max_wrapped_dek_len: usize,
    pub max_transparency_siblings: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeProfile {
    Embedded,
    Strict,
    Server,
}

impl DecodeProfile {
    pub const fn limits(self) -> DecodeLimits {
        match self {
            DecodeProfile::Embedded => DecodeLimits::embedded_profile(),
            DecodeProfile::Strict => DecodeLimits::strict_default(),
            DecodeProfile::Server => DecodeLimits::server_profile(),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            DecodeProfile::Embedded => "embedded",
            DecodeProfile::Strict => "strict",
            DecodeProfile::Server => "server",
        }
    }

    pub fn from_cli_value(value: &str) -> Option<Self> {
        let normalized = value.trim().to_ascii_lowercase();
        match normalized.as_str() {
            "embedded" | "embed" => Some(DecodeProfile::Embedded),
            "strict" | "default" => Some(DecodeProfile::Strict),
            "server" | "srv" => Some(DecodeProfile::Server),
            _ => None,
        }
    }
}

impl core::str::FromStr for DecodeProfile {
    type Err = KyriotesCsk2Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        DecodeProfile::from_cli_value(s).ok_or(KyriotesCsk2Error::Parse("unknown decode profile"))
    }
}

pub fn decode_profile_from_env(var_name: &str) -> DecodeProfile {
    match std::env::var(var_name) {
        Ok(raw) => decode_profile_from_env_value(Some(raw.as_str())),
        Err(_) => DecodeProfile::Strict,
    }
}

pub fn decode_profile_from_env_value(value: Option<&str>) -> DecodeProfile {
    match value.and_then(DecodeProfile::from_cli_value) {
        Some(profile) => profile,
        None => DecodeProfile::Strict,
    }
}

impl DecodeLimits {
    pub const fn strict_default() -> Self {
        Self {
            max_suite_len: 128,
            max_object_id_len: 1024,
            max_payload_ciphertext_len: 8 * 1024 * 1024,
            max_wrappers: 1024,
            max_wrapped_dek_len: 4096,
            max_transparency_siblings: 64,
        }
    }

    pub const fn embedded_profile() -> Self {
        Self {
            max_suite_len: 64,
            max_object_id_len: 256,
            max_payload_ciphertext_len: 256 * 1024,
            max_wrappers: 16,
            max_wrapped_dek_len: 512,
            max_transparency_siblings: 24,
        }
    }

    pub const fn server_profile() -> Self {
        Self {
            max_suite_len: 256,
            max_object_id_len: 4096,
            max_payload_ciphertext_len: 64 * 1024 * 1024,
            max_wrappers: 8192,
            max_wrapped_dek_len: 16 * 1024,
            max_transparency_siblings: 256,
        }
    }
}

impl Default for DecodeLimits {
    fn default() -> Self {
        Self::strict_default()
    }
}

pub fn encode_kyriotes_csk2_object(object: &KyriotesCsk2Object) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    put_u16(&mut out, object.version);
    put_str(&mut out, &object.suite);
    put_str(&mut out, &object.object_id);
    put_rights(&mut out, object.required_rights);
    put_bytes(&mut out, &object.policy_hash);
    put_u64(&mut out, object.seal_epoch);
    put_temporal_policy(&mut out, &object.temporal_policy);
    put_bytes(&mut out, &object.authority_root);
    put_bytes(&mut out, &object.revocation_root);
    put_bytes(&mut out, &object.payload_nonce);
    put_bytes(&mut out, &object.payload_ciphertext);

    put_u32(
        &mut out,
        u32::try_from(object.wrappers.len())
            .expect("Kyriotēs-CSK2 object wrapper count exceeds u32::MAX"),
    );
    for w in &object.wrappers {
        put_u64(&mut out, w.epoch);
        put_bytes(&mut out, &w.kem_ct_classical);
        put_bytes(&mut out, &w.kem_ct_pq);
        put_bytes(&mut out, &w.wrap_nonce);
        put_bytes(&mut out, &w.wrapped_dek);
        put_bytes(&mut out, &w.context_hash);
        put_bytes(&mut out, &w.capability_stamp);
        put_bytes(&mut out, &w.transparency_proof.leaf_hash);
        put_u64(&mut out, w.transparency_proof.leaf_index);
        put_u32(
            &mut out,
            u32::try_from(w.transparency_proof.sibling_hashes.len())
                .expect("transparency proof sibling_hashes count exceeds u32::MAX"),
        );
        for sibling in &w.transparency_proof.sibling_hashes {
            put_bytes(&mut out, sibling);
        }
    }

    out
}

pub fn decode_kyriotes_csk2_object(input: &[u8]) -> Result<KyriotesCsk2Object, KyriotesCsk2Error> {
    decode_kyriotes_csk2_object_with_limits(input, DecodeLimits::default())
}

pub fn decode_kyriotes_csk2_object_with_limits(
    input: &[u8],
    limits: DecodeLimits,
) -> Result<KyriotesCsk2Object, KyriotesCsk2Error> {
    let mut cursor = 0usize;

    if input.len() < MAGIC.len() {
        return Err(KyriotesCsk2Error::Parse("input too short for magic"));
    }
    if &input[..4] != MAGIC {
        return Err(KyriotesCsk2Error::Parse(
            "invalid Kyriotēs-CSK2 object magic",
        ));
    }
    cursor += 4;

    let version = take_u16(input, &mut cursor)?;
    let suite = take_str_limited(input, &mut cursor, limits.max_suite_len)?;
    let object_id = take_str_limited(input, &mut cursor, limits.max_object_id_len)?;
    let required_rights = take_rights(input, &mut cursor)?;
    let policy_hash = take_fixed_limited::<32>(input, &mut cursor, 32)?;
    let seal_epoch = take_u64(input, &mut cursor)?;
    let temporal_policy = take_temporal_policy(input, &mut cursor)?;
    let authority_root = take_fixed_limited::<32>(input, &mut cursor, 32)?;
    let revocation_root = take_fixed_limited::<32>(input, &mut cursor, 32)?;
    let payload_nonce = take_fixed_limited::<12>(input, &mut cursor, 12)?;
    let payload_ciphertext =
        take_bytes_limited(input, &mut cursor, limits.max_payload_ciphertext_len)?;

    let wrappers_len = take_u32(input, &mut cursor)? as usize;
    if wrappers_len > limits.max_wrappers {
        return Err(KyriotesCsk2Error::Parse(
            "wrapper count exceeds maximum allowed",
        ));
    }
    let mut wrappers = Vec::with_capacity(wrappers_len);
    for _ in 0..wrappers_len {
        wrappers.push(AuthorityWrapper {
            epoch: take_u64(input, &mut cursor)?,
            kem_ct_classical: take_fixed_limited::<32>(input, &mut cursor, 32)?,
            kem_ct_pq: take_bytes_limited(input, &mut cursor, limits.max_wrapped_dek_len)?,
            wrap_nonce: take_fixed_limited::<12>(input, &mut cursor, 12)?,
            wrapped_dek: take_bytes_limited(input, &mut cursor, limits.max_wrapped_dek_len)?,
            context_hash: take_fixed_limited::<32>(input, &mut cursor, 32)?,
            capability_stamp: take_fixed_limited::<32>(input, &mut cursor, 32)?,
            transparency_proof: {
                let leaf_hash = take_fixed_limited::<32>(input, &mut cursor, 32)?;
                let leaf_index = take_u64(input, &mut cursor)?;
                let siblings_len = take_u32(input, &mut cursor)? as usize;
                if siblings_len > limits.max_transparency_siblings {
                    return Err(KyriotesCsk2Error::Parse(
                        "transparency sibling count exceeds maximum allowed",
                    ));
                }
                let mut sibling_hashes = Vec::with_capacity(siblings_len);
                for _ in 0..siblings_len {
                    sibling_hashes.push(take_fixed_limited::<32>(input, &mut cursor, 32)?);
                }
                TransparencyProof {
                    leaf_hash,
                    sibling_hashes,
                    leaf_index,
                }
            },
        });
    }

    if cursor != input.len() {
        return Err(KyriotesCsk2Error::Parse(
            "trailing bytes after Kyriotēs-CSK2 object",
        ));
    }

    Ok(KyriotesCsk2Object {
        version,
        suite,
        object_id,
        required_rights,
        policy_hash,
        seal_epoch,
        temporal_policy,
        authority_root,
        revocation_root,
        payload_nonce,
        payload_ciphertext,
        wrappers,
    })
}

// ---------------------------------------------------------------------------
// Capability encode / decode
// ---------------------------------------------------------------------------

/// Encode a [`Capability`] to a self-contained byte string.
///
/// Wire format (all integers little-endian):
/// ```text
/// version (u16-LE)
/// subject (u32-LE length + bytes)
/// object_id (u32-LE length + bytes)
/// rights (u16-LE)
/// policy_hash (u32-LE(32) + 32 bytes)
/// epoch_start (u64-LE)
/// epoch_end (u64-LE)
/// delegation_depth (u64-LE)
/// parent_stamp (u32-LE(32) + 32 bytes)
/// nonce (u32-LE(16) + 16 bytes)
/// ```
pub fn encode_capability(cap: &Capability) -> Vec<u8> {
    let mut out = Vec::new();
    put_u16(&mut out, cap.version);
    put_str(&mut out, &cap.subject);
    put_str(&mut out, &cap.object_id);
    put_rights(&mut out, cap.rights);
    put_bytes(&mut out, &cap.policy_hash);
    put_u64(&mut out, cap.epoch_start);
    put_u64(&mut out, cap.epoch_end);
    put_u64(&mut out, cap.delegation_depth);
    put_bytes(&mut out, &cap.parent_stamp);
    put_bytes(&mut out, &cap.nonce);
    out
}

/// Decode a [`Capability`] using default length limits (1024 bytes for each string field).
pub fn decode_capability(input: &[u8]) -> Result<Capability, KyriotesCsk2Error> {
    decode_capability_with_limits(input, 1024, 1024)
}

/// Decode a [`Capability`] with explicit length limits for the two string fields.
pub fn decode_capability_with_limits(
    input: &[u8],
    max_subject_len: usize,
    max_object_id_len: usize,
) -> Result<Capability, KyriotesCsk2Error> {
    let mut cursor = 0usize;
    let version = take_u16(input, &mut cursor)?;
    let subject = take_str_limited(input, &mut cursor, max_subject_len)?;
    let object_id = take_str_limited(input, &mut cursor, max_object_id_len)?;
    let rights = take_rights(input, &mut cursor)?;
    let policy_hash = take_fixed_limited::<32>(input, &mut cursor, 32)?;
    let epoch_start = take_u64(input, &mut cursor)?;
    let epoch_end = take_u64(input, &mut cursor)?;
    let delegation_depth = take_u64(input, &mut cursor)?;
    let parent_stamp = take_fixed_limited::<32>(input, &mut cursor, 32)?;
    let nonce = take_fixed_limited::<16>(input, &mut cursor, 16)?;

    if cursor != input.len() {
        return Err(KyriotesCsk2Error::Parse("trailing bytes after capability"));
    }

    Ok(Capability {
        version,
        subject,
        object_id,
        rights,
        policy_hash,
        epoch_start,
        epoch_end,
        delegation_depth,
        parent_stamp,
        nonce,
    })
}

// ---------------------------------------------------------------------------
// ThresholdSignatureSet encode / decode
// ---------------------------------------------------------------------------

/// Encode a [`ThresholdSignatureSet`] to bytes.
///
/// Wire format:
/// ```text
/// threshold (u32-LE)
/// count (u32-LE)
/// partials...: signer_index (u32-LE) || sig ([u8; 64] raw, no length prefix)
/// ```
pub fn encode_threshold_signature_set(set: &ThresholdSignatureSet) -> Vec<u8> {
    let mut out = Vec::new();
    put_u32(&mut out, set.threshold);
    put_u32(
        &mut out,
        u32::try_from(set.partials.len()).expect("partial sig count exceeds u32::MAX"),
    );
    for p in &set.partials {
        put_u32(&mut out, p.signer_index);
        out.extend_from_slice(&p.sig);
    }
    out
}

/// Decode a [`ThresholdSignatureSet`] using the default max of 1024 partial signatures.
pub fn decode_threshold_signature_set(
    input: &[u8],
) -> Result<ThresholdSignatureSet, KyriotesCsk2Error> {
    decode_threshold_signature_set_with_max(input, 1024)
}

/// Decode a [`ThresholdSignatureSet`] with an explicit limit on the number of partial sigs.
pub fn decode_threshold_signature_set_with_max(
    input: &[u8],
    max_partials: usize,
) -> Result<ThresholdSignatureSet, KyriotesCsk2Error> {
    let mut cursor = 0usize;
    let threshold = take_u32(input, &mut cursor)?;
    let count = take_u32(input, &mut cursor)? as usize;
    if count > max_partials {
        return Err(KyriotesCsk2Error::Parse(
            "partial signature count exceeds maximum allowed",
        ));
    }
    let mut partials = Vec::with_capacity(count);
    for _ in 0..count {
        let signer_index = take_u32(input, &mut cursor)?;
        if cursor + 64 > input.len() {
            return Err(KyriotesCsk2Error::Parse(
                "unexpected EOF reading partial signature bytes",
            ));
        }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&input[cursor..cursor + 64]);
        cursor += 64;
        partials.push(ThresholdPartialSig { signer_index, sig });
    }

    if cursor != input.len() {
        return Err(KyriotesCsk2Error::Parse(
            "trailing bytes after threshold signature set",
        ));
    }

    Ok(ThresholdSignatureSet {
        threshold,
        partials,
    })
}
