#![no_main]

use kyriotes_csk2::{decode_kyriotes_csk2_object, decode_capability, decode_threshold_signature_set};
use libfuzzer_sys::fuzz_target;

fn fuzz_tsig_surface(data: &[u8]) {
    let signer_a = kyriotes_csk2_fuzz::bytes_to_u64(data);
    let signer_b = kyriotes_csk2_fuzz::bytes_to_u64(data.get(8..).unwrap_or_default());
    let threshold = kyriotes_csk2_fuzz::bytes_to_u64(data.get(16..).unwrap_or_default());
    let partial_count = kyriotes_csk2_fuzz::bytes_to_u64(data.get(24..).unwrap_or_default());

    let _duplicate_signer = signer_a == signer_b;
    let _threshold_zero = threshold == 0;
    let _threshold_exceeds_count = threshold > partial_count;
    let _threshold_satisfied = threshold <= partial_count && threshold != 0;
    let _signer_index_gap = signer_a.abs_diff(signer_b);

    let _ = decode_threshold_signature_set(data);
    let _ = decode_capability(data);
    let _ = decode_kyriotes_csk2_object(data);

    let mutated = kyriotes_csk2_fuzz::mutate_one_byte(data.to_vec(), data.first().copied().unwrap_or(0));
    let _ = decode_threshold_signature_set(&mutated);
    let _ = decode_capability(&mutated);
    let _ = decode_kyriotes_csk2_object(&mutated);

    let truncated = kyriotes_csk2_fuzz::truncate_by_selector(data, data.first().copied().unwrap_or(0));
    let _ = decode_threshold_signature_set(truncated);
    let _ = decode_capability(truncated);
    let _ = decode_kyriotes_csk2_object(truncated);

    let repeated = kyriotes_csk2_fuzz::repeat_small(data, data.first().copied().unwrap_or(0));
    let _ = decode_threshold_signature_set(&repeated);
    let _ = decode_capability(&repeated);
    let _ = decode_kyriotes_csk2_object(&repeated);

    let bomb = kyriotes_csk2_fuzz::append_length_bomb(data.to_vec(), data.first().copied().unwrap_or(0));
    let _ = decode_threshold_signature_set(&bomb);
    let _ = decode_capability(&bomb);
    let _ = decode_kyriotes_csk2_object(&bomb);
}

fuzz_target!(|data: &[u8]| {
    kyriotes_csk2_fuzz::drive_parser_like_targets(data, fuzz_tsig_surface);
});
