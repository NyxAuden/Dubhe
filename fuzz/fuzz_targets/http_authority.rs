#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 8 * 1024 {
        return;
    }
    if let Ok(value) = std::str::from_utf8(data) {
        let _ = dubhe::protocol::http::authority_target(value);
    }
});
