pub mod arc;
pub mod core;
pub mod encoding;

pub use arc::engine::{
    add_epoch_wrapper,
    add_epoch_wrapper_with_verifier,
    open,
    open_with_verifier,
    seal,
    seal_with_verifier,
    validate_capability,
};
pub use arc::kem::{kem_encaps, kem_decaps, hybrid_secret};
pub use arc::model::{
    ArcObject,
    AuthorityState,
    AuthorityWrapper,
    Capability,
    CapabilityProof,
    OpenRequest,
    RecipientKeyPair,
    RecipientPublicKey,
    RecipientSecretKey,
    TransparencyProof,
    capability_leaf_hash,
    capability_stamp,
    context_hash,
    hash_policy,
    transparency_leaf_hash,
};
pub use arc::authority::{
    AuthorityRootKeyPair,
    EpochKeyCert,
    EpochSigningKeyPair,
    capability_issuance_signing_message,
    epoch_cert_signing_message,
    epoch_root_signing_message,
    verify_epoch_cert,
    verify_epoch_root_sig,
};
pub use arc::capability_tree::{
    AuthorityCapabilityTree,
    CapabilityInclusionProof,
    CapabilityIssuanceProof,
    NonRevocationBound,
    NonRevocationWitness,
    verify_capability_inclusion,
    verify_capability_issuance,
    verify_non_revocation,
};
pub use arc::verify::{
    AuthorityEpochEvidence,
    AuthorityEvidenceRegistry,
    AuthorityVerifier,
    BasicAuthorityVerifier,
    CryptoAuthorityVerifier,
    authority_state_signing_message,
};
pub use arc::async_transparency::AsyncTransparencyLog;
pub use arc::transparency::{
    InMemoryTransparencyLog,
    TransparencyLog,
    TransparencyStateCommit,
    hash_transparency_node,
    merkle_root,
};
pub use core::error::ArcError;
pub use core::rights::Rights;
pub use core::temporal::TemporalPolicy;
pub use encoding::wire::{
    DecodeLimits,
    DecodeProfile,
    decode_profile_from_env,
    decode_profile_from_env_value,
    decode_arc_object,
    decode_arc_object_with_limits,
    encode_arc_object,
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
