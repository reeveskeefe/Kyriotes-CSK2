#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    kyriotes_csk2_fuzz::drive_parser_like_targets(data, |candidate| {
        let _ = kyriotes_csk2::decode_kyriotes_csk2_object(candidate);
    });
});
