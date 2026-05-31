#![no_main]

use arc_core::{decode_arc_object, decode_capability, decode_threshold_signature_set};
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

fn fuzz_authority_rotate_surface(data: &[u8]) {
    let root_seed = seed32(data, 0);
    let epoch_seed = seed32(data, 32);
    let alternate_epoch_seed = seed32(data, 64);

    let current_epoch = arc_fuzz::bytes_to_u64(data.get(96..).unwrap_or_default());
    let next_epoch = arc_fuzz::bytes_to_u64(data.get(104..).unwrap_or_default());
    let chain_hint = arc_fuzz::bytes_to_u64(data.get(112..).unwrap_or_default());

    let _root_keypair = arc_core::arc::authority::AuthorityRootKeyPair::from_seed(root_seed);
    let _epoch_keypair = arc_core::arc::authority::EpochSigningKeyPair::from_seed(epoch_seed);
    let _alternate_epoch_keypair =
        arc_core::arc::authority::EpochSigningKeyPair::from_seed(alternate_epoch_seed);

    let _same_epoch = current_epoch == next_epoch;
    let _epoch_regression = next_epoch < current_epoch;
    let _epoch_advance = next_epoch > current_epoch;
    let _epoch_delta = next_epoch.wrapping_sub(current_epoch);
    let _chain_mix = current_epoch ^ next_epoch ^ chain_hint;

    let _ = decode_arc_object(data);
    let _ = decode_capability(data);
    let _ = decode_threshold_signature_set(data);

    let mutated = arc_fuzz::mutate_one_byte(data.to_vec(), data.first().copied().unwrap_or(0));
    let _ = decode_arc_object(&mutated);
    let _ = decode_capability(&mutated);
    let _ = decode_threshold_signature_set(&mutated);

    let truncated = arc_fuzz::truncate_by_selector(data, data.first().copied().unwrap_or(0));
    let _ = decode_arc_object(truncated);
    let _ = decode_capability(truncated);
    let _ = decode_threshold_signature_set(truncated);

    let repeated = arc_fuzz::repeat_small(data, data.first().copied().unwrap_or(0));
    let _ = decode_arc_object(&repeated);
    let _ = decode_capability(&repeated);
    let _ = decode_threshold_signature_set(&repeated);

    let bomb = arc_fuzz::append_length_bomb(data.to_vec(), data.first().copied().unwrap_or(0));
    let _ = decode_arc_object(&bomb);
    let _ = decode_capability(&bomb);
    let _ = decode_threshold_signature_set(&bomb);
}

fuzz_target!(|data: &[u8]| {
    arc_fuzz::drive_parser_like_targets(data, fuzz_authority_rotate_surface);
});
