#![no_main]

use kyriotes_csk2::core::rights::Rights;
use libfuzzer_sys::fuzz_target;

fn fuzz_rights_from_bytes(data: &[u8]) {
    // Rights is a u16 newtype. Extract two u16 values from fuzz input.
    let raw_left     = kyriotes_csk2_fuzz::bytes_to_u64(data) as u16;
    let raw_right    = kyriotes_csk2_fuzz::bytes_to_u64(data.get(8..).unwrap_or_default()) as u16;
    let raw_required = kyriotes_csk2_fuzz::bytes_to_u64(data.get(16..).unwrap_or_default()) as u16;

    let left     = Rights(raw_left);
    let right    = Rights(raw_right);
    let required = Rights(raw_required);

    // --- union -----------------------------------------------------------
    let _ = left.union(right);
    let _ = right.union(left);
    let _ = left.union(left);
    let _ = Rights::empty().union(left);
    let _ = left.union(Rights::empty());

    // --- contains_all ----------------------------------------------------
    let _ = left.contains_all(required);
    let _ = left.contains_all(Rights::empty());
    let _ = Rights::empty().contains_all(required);
    let _ = left.contains_all(left);

    // --- bits ------------------------------------------------------------
    let _ = left.bits();
    let _ = right.bits();
    let _ = Rights::empty().bits();

    // --- named constants exercise ----------------------------------------
    let all = Rights::READ
        .union(Rights::WRITE)
        .union(Rights::APPEND)
        .union(Rights::DELETE)
        .union(Rights::DECRYPT)
        .union(Rights::DELEGATE)
        .union(Rights::EXPORT)
        .union(Rights::EXECUTE)
        .union(Rights::ROTATE)
        .union(Rights::SEAL)
        .union(Rights::UNSEAL);

    let _ = all.contains_all(left);
    let _ = left.contains_all(all);
    let _ = all.union(left);
}

fuzz_target!(|data: &[u8]| {
    kyriotes_csk2_fuzz::drive_parser_like_targets(data, fuzz_rights_from_bytes);
});
