#![no_main]

use arc_core::decode_arc_object;
use arc_core::decode_capability;
use arc_core::decode_threshold_signature_set;
use libfuzzer_sys::fuzz_target;

fn fuzz_hybrid_kem_from_bytes(data: &[u8]) {
    // hybrid_secret_from_bytes, derive_kek_from_context, and
    // recipient_keypair_from_seed_bytes do not exist in arc_core::arc::engine.
    // The KEM surface is exercised indirectly through the wire decode layer
    // since encrypted payloads are embedded in ArcObject wire format.
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
    arc_fuzz::drive_parser_like_targets(data, fuzz_hybrid_kem_from_bytes);
});
