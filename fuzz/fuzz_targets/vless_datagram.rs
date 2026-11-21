#![no_main]

use futures::executor::block_on;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 65_507 {
        return;
    }
    let mut input = data;
    let _ = block_on(dubhe::protocol::vless::read_datagram(
        &mut input, 65_507,
    ));
});
