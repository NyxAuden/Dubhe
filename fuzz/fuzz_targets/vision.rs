#![no_main]

use libfuzzer_sys::fuzz_target;
use dubhe::protocol::vision::Decoder;

fuzz_target!(|data: &[u8]| {
    if data.len() > 64 * 1024 {
        return;
    }
    let mut decoder = Decoder::new([0x11; 16]);
    let mut output = Vec::new();
    let _ = decoder.consume(data, &mut output);

    // 同一输入再按可变块大小喂入，覆盖增量状态。
    let mut decoder = Decoder::new([0x11; 16]);
    let mut output = Vec::new();
    let step = usize::from(data.first().copied().unwrap_or(0) % 17) + 1;
    for chunk in data.chunks(step) {
        if decoder.consume(chunk, &mut output).is_err() {
            break;
        }
    }
});
