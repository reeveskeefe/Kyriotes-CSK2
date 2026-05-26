use arc_core::{OpenRequest, Rights, hash_policy};

pub const DEFAULT_OBJECT_ID: &str = "research-notes.pdf";

pub fn sample_req(epoch: u64, policy_hash: [u8; 32]) -> OpenRequest {
    OpenRequest {
        object_id: DEFAULT_OBJECT_ID.to_string(),
        required_rights: Rights::READ,
        policy_hash,
        epoch,
    }
}

pub fn policy_hash(label: &str) -> [u8; 32] {
    hash_policy(label)
}
