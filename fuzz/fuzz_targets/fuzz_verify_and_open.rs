#![no_main]
use libfuzzer_sys::fuzz_target;
use kyriotes_csk2::/* whatever types you need: AuthorityVerifier, etc. */;

fuzz_target!(|data: &[u8]| {
    // You may need to create minimal valid authority/verifier state for the fuzzer
    // Start simple: just call verify functions that take raw bytes where possible
    let _ = kyriotes_csk2::verify(/* ... */); // adapt to your public API

    // Or roundtrip where possible
    if let Ok(obj) = kyriotes_csk2::decode_kyriotes_csk2_object(data, DecodeLimits::strict()) {
        // Try to verify with a dummy verifier if possible
        let _ = obj.verify(/* dummy state */);
    }
});