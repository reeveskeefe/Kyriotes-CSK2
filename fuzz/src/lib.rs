#![allow(dead_code)]

use arbitrary::{Arbitrary, Unstructured};
use std::panic::{catch_unwind, AssertUnwindSafe};

pub const MAX_FUZZ_CASES_PER_INPUT: usize = 64;
pub const MAX_SLICE_LEN: usize = 524_288;

#[derive(Debug, Clone, Arbitrary)]
pub struct KyriotesCsk2FuzzHeader {
    pub selector: u8,
    pub profile_selector: u8,
    pub mutation_selector: u8,
    pub repeat_count: u8,
    pub offset_a: u16,
    pub offset_b: u16,
    pub len_a: u16,
    pub len_b: u16,
    pub epoch_a: u64,
    pub epoch_b: u64,
    pub rights_a: u64,
    pub rights_b: u64,
    pub stamp_a: u64,
    pub stamp_b: u64,
}

#[derive(Debug, Clone)]
pub struct SplitInput<'a> {
    pub whole: &'a [u8],
    pub a: &'a [u8],
    pub b: &'a [u8],
    pub c: &'a [u8],
    pub d: &'a [u8],
}

pub fn run_no_panic<F>(f: F)
where
    F: FnOnce(),
{
    let _ = catch_unwind(AssertUnwindSafe(f));
}

pub fn bounded(data: &[u8]) -> &[u8] {
    if data.len() > MAX_SLICE_LEN {
        &data[..MAX_SLICE_LEN]
    } else {
        data
    }
}

pub fn parse_header(data: &[u8]) -> Option<(KyriotesCsk2FuzzHeader, &[u8])> {
    let data = bounded(data);
    let mut u = Unstructured::new(data);
    let header = KyriotesCsk2FuzzHeader::arbitrary(&mut u).ok()?;
    Some((header, u.take_rest()))
}

pub fn split_input<'a>(header: &KyriotesCsk2FuzzHeader, rest: &'a [u8]) -> SplitInput<'a> {
    let len = rest.len();

    let start_a = (header.offset_a as usize).min(len);
    let start_b = (header.offset_b as usize).min(len);

    let end_a = start_a.saturating_add(header.len_a as usize).min(len);
    let end_b = start_b.saturating_add(header.len_b as usize).min(len);

    let mid = len / 2;
    let q1 = len / 4;
    let q3 = q1.saturating_mul(3).min(len);

    SplitInput {
        whole: rest,
        a: &rest[start_a..end_a],
        b: &rest[start_b..end_b],
        c: &rest[..mid],
        d: &rest[q1..q3],
    }
}

pub fn mutate_one_byte(mut data: Vec<u8>, selector: u8) -> Vec<u8> {
    if data.is_empty() {
        return data;
    }

    let index = selector as usize % data.len();
    data[index] = data[index]
        .wrapping_add(1)
        .rotate_left((selector % 7) as u32);
    data
}

pub fn truncate_by_selector(data: &[u8], selector: u8) -> &[u8] {
    if data.is_empty() {
        return data;
    }

    let keep = selector as usize % data.len();
    &data[..keep]
}

pub fn append_length_bomb(mut data: Vec<u8>, selector: u8) -> Vec<u8> {
    let patterns: [[u8; 8]; 8] = [
        [0xff; 8],
        [0x7f; 8],
        [0x80, 0, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff],
        [0, 0, 0, 0, 0, 0, 0, 0],
        [1, 0, 0, 0, 0, 0, 0, 0],
        [0, 1, 0, 0, 0, 0, 0, 0],
        [0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe],
    ];
    data.extend_from_slice(&patterns[selector as usize % patterns.len()]);
    data
}

pub fn repeat_small(data: &[u8], repeat_count: u8) -> Vec<u8> {
    let count = (repeat_count as usize % 8).saturating_add(1);
    let mut out = Vec::with_capacity(data.len().saturating_mul(count).min(MAX_SLICE_LEN));
    for _ in 0..count {
        if out.len().saturating_add(data.len()) > MAX_SLICE_LEN {
            break;
        }
        out.extend_from_slice(data);
    }
    out
}

pub fn drive_parser_like_targets<F>(data: &[u8], mut f: F)
where
    F: FnMut(&[u8]),
{
    let Some((header, rest)) = parse_header(data) else {
        return;
    };

    let split = split_input(&header, rest);

    run_no_panic(|| f(split.whole));
    run_no_panic(|| f(split.a));
    run_no_panic(|| f(split.b));
    run_no_panic(|| f(split.c));
    run_no_panic(|| f(split.d));

    let mutated = mutate_one_byte(split.whole.to_vec(), header.mutation_selector);
    run_no_panic(|| f(&mutated));

    let truncated = truncate_by_selector(split.whole, header.selector);
    run_no_panic(|| f(truncated));

    let bomb = append_length_bomb(split.whole.to_vec(), header.profile_selector);
    run_no_panic(|| f(&bomb));

    let repeated = repeat_small(split.a, header.repeat_count);
    run_no_panic(|| f(&repeated));
}

pub fn bytes_to_u64(data: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    let take = data.len().min(8);
    buf[..take].copy_from_slice(&data[..take]);
    u64::from_le_bytes(buf)
}

pub fn bytes_to_u32(data: &[u8]) -> u32 {
    let mut buf = [0u8; 4];
    let take = data.len().min(4);
    buf[..take].copy_from_slice(&data[..take]);
    u32::from_le_bytes(buf)
}

pub fn bytes_to_bool(data: &[u8]) -> bool {
    data.first().copied().unwrap_or(0) & 1 == 1
}
