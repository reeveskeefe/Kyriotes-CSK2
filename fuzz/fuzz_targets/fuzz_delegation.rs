#![no_main]

use arc_core::{decode_arc_object, decode_capability, decode_threshold_signature_set};
use libfuzzer_sys::fuzz_target;

fn fuzz_delegation_surface(data: &[u8]) {
    let parent_rights = arc_fuzz::bytes_to_u64(data);
    let child_rights = arc_fuzz::bytes_to_u64(data.get(8..).unwrap_or_default());
    let parent_epoch_start = arc_fuzz::bytes_to_u64(data.get(16..).unwrap_or_default());
    let parent_epoch_end = arc_fuzz::bytes_to_u64(data.get(24..).unwrap_or_default());
    let child_epoch_start = arc_fuzz::bytes_to_u64(data.get(32..).unwrap_or_default());
    let child_epoch_end = arc_fuzz::bytes_to_u64(data.get(40..).unwrap_or_default());
    let parent_stamp = arc_fuzz::bytes_to_u64(data.get(48..).unwrap_or_default());
    let child_parent_stamp = arc_fuzz::bytes_to_u64(data.get(56..).unwrap_or_default());
    let depth = arc_fuzz::bytes_to_u64(data.get(64..).unwrap_or_default());

    let _rights_subset = (child_rights & !parent_rights) == 0;
    let _rights_escalation = (child_rights & !parent_rights) != 0;
    let _epoch_start_expansion = child_epoch_start < parent_epoch_start;
    let _epoch_end_expansion = child_epoch_end > parent_epoch_end;
    let _epoch_window_inverted = child_epoch_start > child_epoch_end;
    let _parent_stamp_match = parent_stamp == child_parent_stamp;
    let _depth_at_limit = depth >= 255;
    let _depth_next = depth.saturating_add(1);

    let _ = decode_capability(data);
    let _ = decode_arc_object(data);
    let _ = decode_threshold_signature_set(data);

    let mutated = arc_fuzz::mutate_one_byte(data.to_vec(), data.first().copied().unwrap_or(0));
    let _ = decode_capability(&mutated);
    let _ = decode_arc_object(&mutated);
    let _ = decode_threshold_signature_set(&mutated);

    let truncated = arc_fuzz::truncate_by_selector(data, data.first().copied().unwrap_or(0));
    let _ = decode_capability(truncated);
    let _ = decode_arc_object(truncated);
    let _ = decode_threshold_signature_set(truncated);

    let repeated = arc_fuzz::repeat_small(data, data.first().copied().unwrap_or(0));
    let _ = decode_capability(&repeated);
    let _ = decode_arc_object(&repeated);
    let _ = decode_threshold_signature_set(&repeated);

    let bomb = arc_fuzz::append_length_bomb(data.to_vec(), data.first().copied().unwrap_or(0));
    let _ = decode_capability(&bomb);
    let _ = decode_arc_object(&bomb);
    let _ = decode_threshold_signature_set(&bomb);
}

fuzz_target!(|data: &[u8]| {
    arc_fuzz::drive_parser_like_targets(data, fuzz_delegation_surface);
});
