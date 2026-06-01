#![no_main]

use kyriotes_csk2::{decode_kyriotes_csk2_object, decode_capability, decode_threshold_signature_set};
use libfuzzer_sys::fuzz_target;

fn fuzz_compromise_notice_surface(data: &[u8]) {
    let compromised_epoch = kyriotes_csk2_fuzz::bytes_to_u64(data);
    let recovery_epoch = kyriotes_csk2_fuzz::bytes_to_u64(data.get(8..).unwrap_or_default());
    let epoch_key_hint = kyriotes_csk2_fuzz::bytes_to_u64(data.get(16..).unwrap_or_default());
    let recovery_root_hint = kyriotes_csk2_fuzz::bytes_to_u64(data.get(24..).unwrap_or_default());

    let _same_epoch = compromised_epoch == recovery_epoch;
    let _future_recovery = recovery_epoch > compromised_epoch;
    let _stale_recovery = recovery_epoch < compromised_epoch;
    let _epoch_delta = recovery_epoch.wrapping_sub(compromised_epoch);
    let _key_root_mix = epoch_key_hint ^ recovery_root_hint;

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
    kyriotes_csk2_fuzz::drive_parser_like_targets(data, fuzz_compromise_notice_surface);
});
