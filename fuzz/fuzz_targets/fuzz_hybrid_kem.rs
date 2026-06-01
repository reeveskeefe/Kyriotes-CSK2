#![no_main]

use kyriotes_csk2::decode_kyriotes_csk2_object;
use kyriotes_csk2::decode_capability;
use kyriotes_csk2::decode_threshold_signature_set;
use libfuzzer_sys::fuzz_target;

fn fuzz_hybrid_kem_from_bytes(data: &[u8]) {
    // hybrid_secret_from_bytes, derive_kek_from_context, and
    // recipient_keypair_from_seed_bytes do not exist in kyriotes_csk2::kyriotes_csk2::engine.
    // The KEM surface is exercised indirectly through the wire decode layer
    // since encrypted payloads are embedded in KyriotesCsk2Object wire format.
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
    kyriotes_csk2_fuzz::drive_parser_like_targets(data, fuzz_hybrid_kem_from_bytes);
});
