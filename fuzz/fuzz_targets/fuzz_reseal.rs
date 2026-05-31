#![no_main]

use arc_core::{decode_arc_object, decode_capability, decode_threshold_signature_set};
use libfuzzer_sys::fuzz_target;

fn fuzz_reseal_surface(data: &[u8]) {
    let old_recipient_seed = arc_fuzz::bytes_to_u64(data);
    let new_recipient_seed = arc_fuzz::bytes_to_u64(data.get(8..).unwrap_or_default());
    let reseal_epoch = arc_fuzz::bytes_to_u64(data.get(16..).unwrap_or_default());

    let _same_recipient = old_recipient_seed == new_recipient_seed;
    let _recipient_delta = old_recipient_seed.wrapping_sub(new_recipient_seed);
    let _epoch_mix = reseal_epoch ^ old_recipient_seed ^ new_recipient_seed;

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
    arc_fuzz::drive_parser_like_targets(data, fuzz_reseal_surface);
});
