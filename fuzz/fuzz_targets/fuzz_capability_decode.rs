#![no_main]

use arc_core::{decode_capability, decode_threshold_signature_set};
use libfuzzer_sys::fuzz_target;

fn fuzz_capability_like_decoders(data: &[u8]) {
    let _ = decode_capability(data);
    let _ = decode_threshold_signature_set(data);
}

fuzz_target!(|data: &[u8]| {
    arc_fuzz::drive_parser_like_targets(data, fuzz_capability_like_decoders);
});
