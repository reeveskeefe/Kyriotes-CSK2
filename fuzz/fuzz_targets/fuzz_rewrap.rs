#![no_main]

use kyriotes_csk2::{decode_kyriotes_csk2_object, decode_capability};
use libfuzzer_sys::fuzz_target;

fn fuzz_rewrap_surface(data: &[u8]) {
    let from_epoch = kyriotes_csk2_fuzz::bytes_to_u64(data);
    let delta = kyriotes_csk2_fuzz::bytes_to_u64(data.get(8..).unwrap_or_default());
    let to_epoch = from_epoch.wrapping_add(delta);

    let _same_epoch = from_epoch == to_epoch;
    let _backward_epoch = to_epoch < from_epoch;
    let _forward_epoch = to_epoch > from_epoch;
    let _checked_forward = from_epoch.checked_add(delta);
    let _saturating_forward = from_epoch.saturating_add(delta);
    let _epoch_gap = to_epoch.wrapping_sub(from_epoch);

    let _ = decode_kyriotes_csk2_object(data);
    let _ = decode_capability(data);

    let mutated = kyriotes_csk2_fuzz::mutate_one_byte(data.to_vec(), data.first().copied().unwrap_or(0));
    let _ = decode_kyriotes_csk2_object(&mutated);
    let _ = decode_capability(&mutated);

    let truncated = kyriotes_csk2_fuzz::truncate_by_selector(data, data.first().copied().unwrap_or(0));
    let _ = decode_kyriotes_csk2_object(truncated);
    let _ = decode_capability(truncated);

    let repeated = kyriotes_csk2_fuzz::repeat_small(data, data.first().copied().unwrap_or(0));
    let _ = decode_kyriotes_csk2_object(&repeated);
    let _ = decode_capability(&repeated);

    let bomb = kyriotes_csk2_fuzz::append_length_bomb(data.to_vec(), data.first().copied().unwrap_or(0));
    let _ = decode_kyriotes_csk2_object(&bomb);
    let _ = decode_capability(&bomb);
}

fuzz_target!(|data: &[u8]| {
    kyriotes_csk2_fuzz::drive_parser_like_targets(data, fuzz_rewrap_surface);
});
