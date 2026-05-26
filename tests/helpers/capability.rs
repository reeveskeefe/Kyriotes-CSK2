use arc_core::{Capability, CapabilityProof, Rights};

use super::request_builders::DEFAULT_OBJECT_ID;

pub fn sample_cap(epoch_start: u64, epoch_end: u64, policy_hash: [u8; 32]) -> Capability {
    Capability {
        subject: "keefe".to_string(),
        object_id: DEFAULT_OBJECT_ID.to_string(),
        rights: Rights::READ.union(Rights::DECRYPT),
        policy_hash,
        epoch_start,
        epoch_end,
        nonce: [7u8; 16],
    }
}

pub fn sample_proof() -> CapabilityProof {
    CapabilityProof {
        inclusion_valid: true,
        non_revoked: true,
        issued_signature_valid: true,
    }
}
