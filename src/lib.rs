pub mod arc;
pub mod core;
pub mod encoding;

pub use arc::async_transparency::AsyncTransparencyLog;
pub use arc::authority::{
    AuthorityRootKeyPair, EpochKeyCert, EpochSigningKeyPair, capability_issuance_signing_message,
    compromise_notice_signing_message, epoch_cert_signing_message, epoch_root_signing_message,
    verify_compromise_notice, verify_epoch_cert, verify_epoch_root_sig,
};
pub use arc::capability_tree::{
    AuthorityCapabilityTree, CapabilityInclusionProof, CapabilityIssuanceProof, NonRevocationBound,
    NonRevocationWitness, verify_capability_inclusion, verify_capability_issuance,
    verify_non_revocation,
};
pub use arc::engine::{
    EpochRotation, MAX_DELEGATION_DEPTH, add_epoch_wrapper, add_epoch_wrapper_and_commit,
    add_epoch_wrapper_with_verifier, check_epoch_not_compromised, delegate_capability,
    issue_capability, issue_capability_and_commit, open, open_and_reseal,
    open_and_reseal_and_commit, open_and_reseal_with_verifier, open_with_compromise_check,
    open_with_compromise_check_and_verifier, open_with_verifier, revoke_capability,
    revoke_capability_and_commit, revoke_capability_and_commit_async, rotate_epoch,
    rotate_epoch_and_commit, rotate_epoch_full, seal, seal_and_commit, seal_with_verifier,
    validate_capability, verify, verify_with_compromise_check,
    verify_with_compromise_check_and_verifier, verify_with_verifier,
};
pub use arc::kem::{hybrid_secret, kem_decaps, kem_encaps};
pub use arc::model::{
    ArcObject, AuthorityState, AuthorityWrapper, Capability, CapabilityProof, CompromiseNotice,
    OpenRequest, RecipientKeyPair, RecipientPublicKey, RecipientSecretKey, TransparencyProof,
    capability_leaf_hash, capability_stamp, context_hash, hash_policy, transparency_leaf_hash,
};
pub use arc::model::{ML_KEM_768_CT_BYTES, ML_KEM_768_DK_BYTES, ML_KEM_768_EK_BYTES};
pub use arc::transparency::{
    InMemoryTransparencyLog, TransparencyLog, TransparencyStateCommit, hash_transparency_node,
    merkle_root, transparency_log_entry_hash,
};
pub use arc::tsig::{
    ThresholdPartialSig, ThresholdSignatureSet, tsig_epoch_signing_message, tsig_sign, tsig_verify,
};
pub use arc::verify::{
    AuthorityEpochEvidence, AuthorityEvidenceRegistry, AuthorityVerifier, BasicAuthorityVerifier,
    CryptoAuthorityVerifier, TsigEvidence, authority_state_signing_message,
};
pub use core::error::ArcError;
pub use core::rights::Rights;
pub use core::temporal::TemporalPolicy;
pub use encoding::wire::{
    DecodeLimits, DecodeProfile, decode_arc_object, decode_arc_object_with_limits,
    decode_capability, decode_capability_with_limits, decode_profile_from_env,
    decode_profile_from_env_value, decode_threshold_signature_set,
    decode_threshold_signature_set_with_max, encode_arc_object, encode_capability,
    encode_threshold_signature_set,
};

#[cfg(test)]
mod smoke {
    use super::*;

    #[test]
    fn rights_union_and_contains() {
        let grant = Rights::READ.union(Rights::DECRYPT);
        assert!(grant.contains_all(Rights::READ));
        assert!(!grant.contains_all(Rights::WRITE));
    }
}

#[cfg(kani)]
mod kani_context_hash_equivalence;

#[cfg(kani)]
mod kani_decode_arc_object_equivalence;

#[cfg(kani)]
mod kani_encode_arc_object_equivalence;

#[cfg(kani)]
mod kani_verify_equivalence;

#[cfg(kani)]
mod kani_seal_equivalence;

#[cfg(kani)]
mod kani_open_equivalence;

#[cfg(kani)]
mod kani_add_epoch_wrapper_equivalence;

#[cfg(kani)]
mod kani_rotate_epoch_equivalence;
