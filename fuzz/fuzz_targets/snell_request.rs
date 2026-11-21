#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 64 * 1024 {
        return;
    }
    for version in [4, 5, 6] {
        dubhe::fuzzing::snell_parse_request(data, version);
    }
});
