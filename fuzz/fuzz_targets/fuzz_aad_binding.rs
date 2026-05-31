#![no_main]

use arc_core::decode_arc_object;
use arc_core::decode_capability;
use arc_core::decode_threshold_signature_set;
use libfuzzer_sys::fuzz_target;

fn fuzz_aad_from_bytes(data: &[u8]) {
    // verify() requires 5 args we can't construct from raw bytes alone,
    // so we exercise the decode surface instead — which is what this
    // target actually needs to stress (AAD is embedded in the wire format).
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
    arc_fuzz::drive_parser_like_targets(data, fuzz_aad_from_bytes);
});
