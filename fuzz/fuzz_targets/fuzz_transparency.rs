#![no_main]

use kyriotes_csk2::kyriotes_csk2::transparency::{
    hash_transparency_node, merkle_root, transparency_log_entry_hash,
};
use kyriotes_csk2::{decode_kyriotes_csk2_object, decode_capability, decode_threshold_signature_set};
use libfuzzer_sys::fuzz_target;

fn seed32(data: &[u8], offset: usize) -> [u8; 32] {
    let mut out = [0u8; 32];
    if offset < data.len() {
        let available = &data[offset..];
        let take = available.len().min(32);
        out[..take].copy_from_slice(&available[..take]);
    }
    out
}

fn seed64(data: &[u8], offset: usize) -> [u8; 64] {
    let mut out = [0u8; 64];
    if offset < data.len() {
        let available = &data[offset..];
        let take = available.len().min(64);
        out[..take].copy_from_slice(&available[..take]);
    }
    out
}

fn fuzz_transparency_surface(data: &[u8]) {
    let prev_hash = seed32(data, 0);
    let authority_root = seed32(data, 32);
    let revoc_root = seed32(data, 64);
    let epoch_pk = seed32(data, 96);
    let epoch_root_sig = seed64(data, 128);
    let extra = seed32(data, 192);
    let epoch = kyriotes_csk2_fuzz::bytes_to_u64(data.get(200..).unwrap_or_default());

    // --- hash_transparency_node ------------------------------------------
    let _ = hash_transparency_node(prev_hash, authority_root);
    let _ = hash_transparency_node(authority_root, prev_hash);
    let _ = hash_transparency_node(prev_hash, prev_hash);
    let _ = hash_transparency_node([0u8; 32], [0u8; 32]);

    // --- transparency_log_entry_hash -------------------------------------
    let _ = transparency_log_entry_hash(
        &prev_hash,
        &authority_root,
        &revoc_root,
        epoch,
        &epoch_pk,
        &epoch_root_sig,
    );
    let _ = transparency_log_entry_hash(
        &prev_hash,
        &authority_root,
        &revoc_root,
        0,
        &epoch_pk,
        &epoch_root_sig,
    );
    let _ = transparency_log_entry_hash(
        &prev_hash,
        &authority_root,
        &revoc_root,
        u64::MAX,
        &epoch_pk,
        &epoch_root_sig,
    );
    let _ = transparency_log_entry_hash(
        &[0u8; 32], &[0u8; 32], &[0u8; 32], 0, &[0u8; 32], &[0u8; 64],
    );
    let _ = transparency_log_entry_hash(
        &prev_hash,
        &authority_root,
        &revoc_root,
        epoch.wrapping_add(1),
        &epoch_pk,
        &epoch_root_sig,
    );

    // --- merkle_root -----------------------------------------------------
    let _ = merkle_root(&[]);
    let _ = merkle_root(&[prev_hash]);
    let _ = merkle_root(&[prev_hash, authority_root]);
    let _ = merkle_root(&[prev_hash, authority_root, revoc_root]);
    let _ = merkle_root(&[prev_hash, authority_root, revoc_root, extra]);

    let leaf_count = (data.first().copied().unwrap_or(0) as usize % 16) + 1;
    let leaves: Vec<[u8; 32]> = (0..leaf_count)
        .map(|i| seed32(data, i.wrapping_mul(7)))
        .collect();
    let _ = merkle_root(&leaves);

    // --- wire-decode layer -----------------------------------------------
    let _ = decode_kyriotes_csk2_object(data);
    let _ = decode_capability(data);
    let _ = decode_threshold_signature_set(data);

    let mutated = kyriotes_csk2_fuzz::mutate_one_byte(data.to_vec(), data.first().copied().unwrap_or(0));
    let _ = decode_kyriotes_csk2_object(&mutated);
    let _ = decode_capability(&mutated);
    let _ = decode_threshold_signature_set(&mutated);

    let truncated = kyriotes_csk2_fuzz::truncate_by_selector(data, data.first().copied().unwrap_or(0));
    let _ = decode_kyriotes_csk2_object(truncated);
    let _ = decode_capability(truncated);
    let _ = decode_threshold_signature_set(truncated);

    let repeated = kyriotes_csk2_fuzz::repeat_small(data, data.first().copied().unwrap_or(0));
    let _ = decode_kyriotes_csk2_object(&repeated);
    let _ = decode_capability(&repeated);
    let _ = decode_threshold_signature_set(&repeated);

    let bomb = kyriotes_csk2_fuzz::append_length_bomb(data.to_vec(), data.first().copied().unwrap_or(0));
    let _ = decode_kyriotes_csk2_object(&bomb);
    let _ = decode_capability(&bomb);
    let _ = decode_threshold_signature_set(&bomb);
}

fuzz_target!(|data: &[u8]| {
    kyriotes_csk2_fuzz::drive_parser_like_targets(data, fuzz_transparency_surface);
});
