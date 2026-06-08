#![no_main]

use kyriotes_csk2::{
    decode_capability, decode_capability_with_limits, decode_kyriotes_csk2_object,
    decode_kyriotes_csk2_object_with_limits, decode_threshold_signature_set,
    decode_threshold_signature_set_with_max, encode_capability, encode_kyriotes_csk2_object,
    encode_threshold_signature_set, DecodeProfile,
};
use libfuzzer_sys::fuzz_target;

fn fuzz_object_codec(data: &[u8]) {
    if let Ok(value) = decode_kyriotes_csk2_object(data) {
        let canonical = encode_kyriotes_csk2_object(&value);
        assert_eq!(canonical, data, "accepted object bytes must be canonical");
        assert_eq!(
            decode_kyriotes_csk2_object(&canonical).expect("canonical object must decode"),
            value
        );

        for profile in [
            DecodeProfile::Embedded,
            DecodeProfile::Strict,
            DecodeProfile::Server,
        ] {
            if let Ok(profile_value) =
                decode_kyriotes_csk2_object_with_limits(&canonical, profile.limits())
            {
                assert_eq!(profile_value, value);
            }
        }

        let mut trailing = canonical;
        trailing.push(0);
        assert!(
            decode_kyriotes_csk2_object(&trailing).is_err(),
            "trailing object bytes must reject"
        );
    }
}

fn fuzz_capability_codec(data: &[u8]) {
    if let Ok(value) = decode_capability(data) {
        let canonical = encode_capability(&value);
        assert_eq!(
            canonical, data,
            "accepted capability bytes must be canonical"
        );
        assert_eq!(
            decode_capability(&canonical).expect("canonical capability must decode"),
            value
        );
        assert_eq!(
            decode_capability_with_limits(&canonical, usize::MAX, usize::MAX)
                .expect("relaxed limits must accept canonical capability"),
            value
        );

        let mut trailing = canonical;
        trailing.push(0);
        assert!(
            decode_capability(&trailing).is_err(),
            "trailing capability bytes must reject"
        );
    }
}

fn fuzz_threshold_signature_codec(data: &[u8]) {
    if let Ok(value) = decode_threshold_signature_set(data) {
        let canonical = encode_threshold_signature_set(&value);
        assert_eq!(
            canonical, data,
            "accepted threshold-signature bytes must be canonical"
        );
        let decoded = decode_threshold_signature_set(&canonical)
            .expect("canonical threshold-signature set must decode");
        assert_eq!(encode_threshold_signature_set(&decoded), canonical);
        let exact_limit = decode_threshold_signature_set_with_max(&canonical, value.partials.len())
            .expect("exact partial limit must accept canonical set");
        assert_eq!(encode_threshold_signature_set(&exact_limit), canonical);

        let mut trailing = canonical;
        trailing.push(0);
        assert!(
            decode_threshold_signature_set(&trailing).is_err(),
            "trailing threshold-signature bytes must reject"
        );
    }
}

fuzz_target!(|data: &[u8]| {
    let data = kyriotes_csk2_fuzz::bounded(data);
    fuzz_object_codec(data);
    fuzz_capability_codec(data);
    fuzz_threshold_signature_codec(data);
});
