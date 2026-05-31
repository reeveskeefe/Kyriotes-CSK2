#![no_main]

use arc_core::{DecodeProfile, decode_profile_from_env, decode_profile_from_env_value};
use std::str::FromStr;
use libfuzzer_sys::fuzz_target;

fn fuzz_decode_profile_from_bytes(data: &[u8]) {
    let as_utf8 = std::str::from_utf8(data).unwrap_or("");

    let _ = DecodeProfile::from_cli_value(as_utf8);
    let _ = DecodeProfile::from_str(as_utf8);

    for profile in [DecodeProfile::Embedded, DecodeProfile::Strict, DecodeProfile::Server] {
        let _ = profile.limits();
        let _ = profile.as_str();
    }

    for profile in [DecodeProfile::Embedded, DecodeProfile::Strict, DecodeProfile::Server] {
        let s = profile.as_str();
        let _ = DecodeProfile::from_cli_value(s);
        let _ = DecodeProfile::from_str(s);
    }

    let _ = decode_profile_from_env_value(std::str::from_utf8(data).ok());
    let _ = decode_profile_from_env(as_utf8);
}

fuzz_target!(|data: &[u8]| {
    arc_fuzz::drive_parser_like_targets(data, fuzz_decode_profile_from_bytes);
});
