#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    arc_fuzz::drive_parser_like_targets(data, |candidate| {
        let _ = arc_core::decode_arc_object(candidate);
    });
});
