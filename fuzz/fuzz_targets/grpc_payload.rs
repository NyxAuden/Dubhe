#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 64 * 1024 {
        return;
    }
    let multi = data.first().is_some_and(|byte| byte & 1 == 1);
    dubhe::fuzzing::grpc_decode_payload(data, multi);
});
