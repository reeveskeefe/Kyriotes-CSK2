#![no_main]

use arc_core::{decode_arc_object, decode_capability};
use libfuzzer_sys::fuzz_target;

fn fuzz_temporal_policy_surface(data: &[u8]) {
    let epoch_a = arc_fuzz::bytes_to_u64(data);
    let epoch_b = arc_fuzz::bytes_to_u64(data.get(8..).unwrap_or_default());
    let epoch_c = arc_fuzz::bytes_to_u64(data.get(16..).unwrap_or_default());

    let _ = epoch_a.checked_add(epoch_b);
    let _ = epoch_a.checked_sub(epoch_b);
    let _ = epoch_a.saturating_add(epoch_b);
    let _ = epoch_a.saturating_sub(epoch_b);
    let _ = epoch_a.wrapping_add(epoch_b);
    let _ = epoch_a.wrapping_sub(epoch_b);

    let start = epoch_a.min(epoch_b);
    let end = epoch_a.max(epoch_b);

    let _inside_start = start <= epoch_c && epoch_c <= end;
    let _inside_end = start <= end;
    let _same_epoch = epoch_a == epoch_b;
    let _backward = epoch_b < epoch_a;
    let _forward = epoch_b > epoch_a;

    let _ = decode_arc_object(data);
    let _ = decode_capability(data);

    let mutated = arc_fuzz::mutate_one_byte(data.to_vec(), data.first().copied().unwrap_or(0));
    let _ = decode_arc_object(&mutated);
    let _ = decode_capability(&mutated);

    let truncated = arc_fuzz::truncate_by_selector(data, data.first().copied().unwrap_or(0));
    let _ = decode_arc_object(truncated);
    let _ = decode_capability(truncated);

    let bomb = arc_fuzz::append_length_bomb(data.to_vec(), data.first().copied().unwrap_or(0));
    let _ = decode_arc_object(&bomb);
    let _ = decode_capability(&bomb);
}

fuzz_target!(|data: &[u8]| {
    arc_fuzz::drive_parser_like_targets(data, fuzz_temporal_policy_surface);
});
