#![no_main]

use futures::executor::block_on;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 64 * 1024 {
        return;
    }
    let mut input = data;
    let _ = block_on(dubhe::protocol::xudp::read(&mut input, 65_507));
});
