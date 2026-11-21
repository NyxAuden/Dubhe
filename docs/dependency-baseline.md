# 锁定依赖许可清单

由 `python3 -I tools/dependency_report.py --output docs/dependency-baseline.md` 从 Cargo.lock 对应元数据生成。

包含全部目标平台和开发依赖，不代表它们都链接到每个发布产物。SPDX 来自包元数据，非完整法律审计；分发时需保留选用许可及相关声明。项目自身 `publish=false`、许可证为 GPL-3.0-only。未移植Xray/sing-box/Nowhere实现代码；MIT Shadowsocks协议依赖的本地缓存/严格校验/操作预算补丁及来源见 vendor/shadowsocks/PATCH.md 和 UPSTREAM.json，原许可原样保留。

工具链：`rust-toolchain.toml` 固定 Rust 1.91.0；声明 MSRV 1.91，依赖解析按该版本约束。声明门槛不等于实际构建验证，具体平台/MSRV结果见对应验收报告；Shadowsocks组合已用Linux ARM64精确Rust1.91.0及1.91.1分别执行all-targets check（含AWS-LC原生编译），编译检查不等于该工具链全部运行测试；各平台结果见shadowsocks-acceptance.md。

直接库选择：Tokio、Serde、rustls/ring、Hickory 0.26、SHA-2/subtle及Shadowsocks协议层。后者显式关闭默认features，只启用AEAD2017/2022和本地UDP缓存禁用feature，新增AWS-LC不替换TLS的ring。workspace全量元数据包含可选/开发/跨平台包，不代表生产启用它们；以 cargo tree -p dubhe -e features 的实际特性树为准。依赖公告门禁见 deny.toml 与 tools/supply-chain.sh；仍需独立做漏洞和更新审查。

| 包 | 版本 | 类别 | 声明许可 | 声明 Rust 版本 |
|---|---|---|---|---|
| aead | 0.5.2 | 传递 | MIT OR Apache-2.0 | 1.56 |
| aead | 0.6.1 | 传递 | MIT OR Apache-2.0 | 1.85 |
| aes | 0.9.4 | 直接（含开发） | MIT OR Apache-2.0 | 1.89 |
| aes-gcm | 0.11.1 | 直接（含开发） | Apache-2.0 OR MIT | 1.85 |
| aho-corasick | 1.1.5 | 传递 | Unlicense OR MIT | 1.60.0 |
| android_system_properties | 0.1.6 | 传递 | MIT OR Apache-2.0 | 未声明 |
| anstream | 1.0.0 | 传递 | MIT OR Apache-2.0 | 1.66.0 |
| anstyle | 1.0.14 | 传递 | MIT OR Apache-2.0 | 1.66.0 |
| anstyle-parse | 1.0.0 | 传递 | MIT OR Apache-2.0 | 1.66.0 |
| anstyle-query | 1.1.5 | 传递 | MIT OR Apache-2.0 | 1.66.0 |
| anstyle-wincon | 3.0.11 | 传递 | MIT OR Apache-2.0 | 1.66.0 |
| anyhow | 1.0.104 | 直接（含开发） | MIT OR Apache-2.0 | 1.68 |
| arc-swap | 1.9.3 | 传递 | MIT OR Apache-2.0 | 未声明 |
| argon2 | 0.5.3 | 直接（含开发） | MIT OR Apache-2.0 | 1.65 |
| arrayvec | 0.7.8 | 传递 | MIT OR Apache-2.0 | 1.51 |
| asn1-rs | 0.7.2 | 传递 | MIT OR Apache-2.0 | 1.68 |
| asn1-rs-derive | 0.6.0 | 传递 | MIT OR Apache-2.0 | 未声明 |
| asn1-rs-impl | 0.2.0 | 传递 | MIT/Apache-2.0 | 未声明 |
| async-trait | 0.1.92 | 传递 | MIT OR Apache-2.0 | 1.71 |
| atomic-waker | 1.1.2 | 传递 | Apache-2.0 OR MIT | 1.36 |
| autocfg | 1.5.1 | 传递 | Apache-2.0 OR MIT | 1.0 |
| aws-lc-rs | 1.19.0 | 直接（含开发） | ISC AND (Apache-2.0 OR ISC) | 1.71.0 |
| aws-lc-sys | 0.47.0 | 传递 | ISC AND (Apache-2.0 OR ISC) AND Apache-2.0 AND MIT AND BSD-3-Clause AND (Apache-2.0 OR ISC OR MIT) AND (Apache-2.0 OR ISC OR MIT-0) | 1.71.0 |
| base64 | 0.22.1 | 直接（含开发） | MIT OR Apache-2.0 | 1.48.0 |
| base64 | 0.23.1 | 直接（含开发） | MIT OR Apache-2.0 | 1.71.0 |
| base64ct | 1.8.3 | 传递 | Apache-2.0 OR MIT | 1.85 |
| bit-vec | 0.9.1 | 传递 | Apache-2.0 OR MIT | 1.82 |
| bitflags | 1.3.2 | 传递 | MIT/Apache-2.0 | 未声明 |
| bitflags | 2.13.2 | 传递 | MIT OR Apache-2.0 | 1.56.0 |
| blake2 | 0.10.6 | 直接（含开发） | MIT OR Apache-2.0 | 未声明 |
| blake3 | 1.8.7 | 直接（含开发） | CC0-1.0 OR Apache-2.0 OR Apache-2.0 WITH LLVM-exception | 未声明 |
| block-buffer | 0.10.4 | 传递 | MIT OR Apache-2.0 | 未声明 |
| block-buffer | 0.12.1 | 传递 | MIT OR Apache-2.0 | 1.85 |
| boringtun | 0.7.1 | 直接（含开发） | BSD-3-Clause | 未声明 |
| bumpalo | 3.20.3 | 传递 | MIT OR Apache-2.0 | 1.71.1 |
| byte_string | 1.0.0 | 传递 | MIT/Apache-2.0 | 未声明 |
| byteorder | 1.5.0 | 传递 | Unlicense OR MIT | 1.60 |
| bytes | 1.12.1 | 直接（含开发） | MIT | 1.57 |
| cc | 1.11.0 | 传递 | MIT OR Apache-2.0 | 1.65.0 |
| cfg-if | 1.0.5 | 传递 | MIT OR Apache-2.0 | 1.32 |
| cfg_aliases | 0.2.2 | 传递 | MIT | 未声明 |
| chacha20 | 0.10.2 | 传递 | MIT OR Apache-2.0 | 1.85 |
| chacha20 | 0.9.1 | 传递 | Apache-2.0 OR MIT | 1.56 |
| chacha20poly1305 | 0.10.1 | 直接（含开发） | Apache-2.0 OR MIT | 未声明 |
| chacha20poly1305 | 0.11.0 | 直接（含开发） | Apache-2.0 OR MIT | 1.85 |
| chrono | 0.4.45 | 传递 | MIT OR Apache-2.0 | 1.62.0 |
| cipher | 0.4.4 | 传递 | MIT OR Apache-2.0 | 1.56 |
| cipher | 0.5.2 | 传递 | MIT OR Apache-2.0 | 1.85 |
| clap | 4.6.7 | 直接（含开发） | MIT OR Apache-2.0 | 1.85 |
| clap_builder | 4.6.7 | 传递 | MIT OR Apache-2.0 | 1.85 |
| clap_derive | 4.6.7 | 传递 | MIT OR Apache-2.0 | 1.85 |
| clap_lex | 1.1.1 | 传递 | MIT OR Apache-2.0 | 1.85 |
| cmake | 0.1.58 | 传递 | MIT OR Apache-2.0 | 1.65 |
| cmov | 0.5.4 | 传递 | Apache-2.0 OR MIT | 1.85 |
| colorchoice | 1.0.5 | 传递 | MIT OR Apache-2.0 | 1.66.0 |
| combine | 4.6.9 | 传递 | MIT | 未声明 |
| const-oid | 0.10.2 | 传递 | Apache-2.0 OR MIT | 1.85 |
| constant_time_eq | 0.4.2 | 传递 | CC0-1.0 OR MIT-0 OR Apache-2.0 | 1.85.0 |
| core-foundation | 0.10.1 | 传递 | MIT OR Apache-2.0 | 1.65 |
| core-foundation | 0.9.4 | 传递 | MIT OR Apache-2.0 | 未声明 |
| core-foundation-sys | 0.8.7 | 传递 | MIT OR Apache-2.0 | 未声明 |
| cpubits | 0.1.1 | 传递 | MIT OR Apache-2.0 | 1.85 |
| cpufeatures | 0.2.17 | 传递 | MIT OR Apache-2.0 | 未声明 |
| cpufeatures | 0.3.1 | 传递 | MIT OR Apache-2.0 | 1.85 |
| crc32fast | 1.5.4 | 直接（含开发） | MIT OR Apache-2.0 | 1.63 |
| critical-section | 1.2.0 | 传递 | MIT OR Apache-2.0 | 未声明 |
| crossbeam-channel | 0.5.17 | 传递 | MIT OR Apache-2.0 | 1.60 |
| crossbeam-epoch | 0.9.21 | 传递 | MIT OR Apache-2.0 | 1.61 |
| crossbeam-utils | 0.8.23 | 传递 | MIT OR Apache-2.0 | 1.60 |
| crypto-common | 0.1.7 | 传递 | MIT OR Apache-2.0 | 未声明 |
| crypto-common | 0.2.2 | 传递 | MIT OR Apache-2.0 | 1.85 |
| cryptoxide | 0.5.1 | 直接（含开发） | MIT/Apache-2.0 | 1.78 |
| ctr | 0.10.1 | 直接（含开发） | MIT OR Apache-2.0 | 1.85 |
| ctutils | 0.4.8 | 传递 | Apache-2.0 OR MIT | 1.87 |
| curve25519-dalek | 4.1.3 | 传递 | BSD-3-Clause | 1.60.0 |
| curve25519-dalek-derive | 0.1.1 | 传递 | MIT/Apache-2.0 | 未声明 |
| data-encoding | 2.11.1 | 传递 | MIT | 1.48 |
| defmt | 1.2.0 | 传递 | MIT OR Apache-2.0 | 1.81 |
| defmt-macros | 1.2.0 | 传递 | MIT OR Apache-2.0 | 未声明 |
| defmt-parser | 1.1.0 | 传递 | MIT OR Apache-2.0 | 1.81 |
| der | 0.8.3 | 传递 | Apache-2.0 OR MIT | 1.85 |
| der-parser | 10.0.0 | 传递 | MIT OR Apache-2.0 | 1.63 |
| deranged | 0.5.9 | 传递 | MIT OR Apache-2.0 | 1.85.0 |
| digest | 0.10.7 | 传递 | MIT OR Apache-2.0 | 未声明 |
| digest | 0.11.3 | 传递 | MIT OR Apache-2.0 | 1.85 |
| displaydoc | 0.2.7 | 传递 | MIT OR Apache-2.0 | 1.71.0 |
| dunce | 1.0.5 | 传递 | CC0-1.0 OR MIT-0 OR Apache-2.0 | 未声明 |
| dynosaur | 0.3.1 | 传递 | MIT OR Apache-2.0 | 1.84 |
| dynosaur_derive | 0.3.1 | 传递 | MIT OR Apache-2.0 | 1.84 |
| either | 1.19.0 | 传递 | MIT OR Apache-2.0 | 1.63.0 |
| env_filter | 2.0.0 | 传递 | MIT OR Apache-2.0 | 1.71 |
| env_logger | 0.11.11 | 传递 | MIT OR Apache-2.0 | 1.71 |
| equivalent | 1.0.3 | 传递 | Apache-2.0 OR MIT | 1.6 |
| errno | 0.3.14 | 传递 | MIT OR Apache-2.0 | 1.56 |
| fastbloom | 0.17.0 | 传递 | MIT OR Apache-2.0 | 1.70 |
| fastrand | 2.5.0 | 传递 | Apache-2.0 OR MIT | 1.63 |
| fiat-crypto | 0.2.9 | 传递 | MIT OR Apache-2.0 OR BSD-1-Clause | 未声明 |
| find-msvc-tools | 0.1.15 | 传递 | MIT OR Apache-2.0 | 1.65.0 |
| fnv | 1.0.7 | 传递 | Apache-2.0 / MIT | 未声明 |
| foldhash | 0.2.0 | 传递 | Zlib | 1.60 |
| form_urlencoded | 1.2.2 | 传递 | MIT OR Apache-2.0 | 1.51 |
| fs_extra | 1.3.0 | 传递 | MIT | 未声明 |
| futures | 0.3.34 | 传递 | MIT OR Apache-2.0 | 1.71 |
| futures-channel | 0.3.34 | 传递 | MIT OR Apache-2.0 | 1.71 |
| futures-core | 0.3.34 | 传递 | MIT OR Apache-2.0 | 1.36 |
| futures-executor | 0.3.34 | 传递 | MIT OR Apache-2.0 | 1.71 |
| futures-io | 0.3.34 | 传递 | MIT OR Apache-2.0 | 1.36 |
| futures-macro | 0.3.34 | 传递 | MIT OR Apache-2.0 | 1.71 |
| futures-sink | 0.3.34 | 传递 | MIT OR Apache-2.0 | 1.36 |
| futures-task | 0.3.34 | 传递 | MIT OR Apache-2.0 | 1.71 |
| futures-util | 0.3.34 | 直接（含开发） | MIT OR Apache-2.0 | 1.71 |
| generic-array | 0.14.7 | 传递 | MIT | 未声明 |
| getrandom | 0.2.17 | 传递 | MIT OR Apache-2.0 | 未声明 |
| getrandom | 0.4.3 | 传递 | MIT OR Apache-2.0 | 1.85 |
| ghash | 0.6.0 | 传递 | Apache-2.0 OR MIT | 1.85 |
| h2 | 0.4.20 | 直接（含开发） | MIT | 1.63 |
| h3 | 0.0.8 | 直接（含开发） | MIT | 1.70 |
| h3-datagram | 0.0.2 | 直接（含开发） | MIT | 未声明 |
| h3-quinn | 0.0.10 | 直接（含开发） | MIT | 1.70 |
| hash32 | 0.3.1 | 传递 | MIT OR Apache-2.0 | 未声明 |
| hashbrown | 0.17.1 | 传递 | MIT OR Apache-2.0 | 1.85.0 |
| heapless | 0.9.3 | 传递 | MIT OR Apache-2.0 | 1.87 |
| heck | 0.5.0 | 传递 | MIT OR Apache-2.0 | 1.56 |
| hex | 0.4.3 | 传递 | MIT OR Apache-2.0 | 未声明 |
| hickory-net | 0.26.3 | 传递 | MIT OR Apache-2.0 | 1.88 |
| hickory-proto | 0.26.3 | 传递 | MIT OR Apache-2.0 | 1.88 |
| hickory-resolver | 0.26.2 | 直接（含开发） | MIT OR Apache-2.0 | 1.88 |
| hkdf | 0.13.0 | 传递 | MIT OR Apache-2.0 | 1.85 |
| hmac | 0.12.1 | 传递 | MIT OR Apache-2.0 | 未声明 |
| hmac | 0.13.0 | 传递 | MIT OR Apache-2.0 | 1.85 |
| http | 1.5.0 | 直接（含开发） | MIT OR Apache-2.0 | 1.57.0 |
| httparse | 1.10.1 | 直接（含开发） | MIT OR Apache-2.0 | 未声明 |
| humantime | 2.4.0 | 传递 | MIT OR Apache-2.0 | 1.60 |
| hybrid-array | 0.4.15 | 传递 | MIT OR Apache-2.0 | 1.85 |
| iana-time-zone | 0.1.65 | 传递 | MIT OR Apache-2.0 | 1.62.0 |
| iana-time-zone-haiku | 0.1.2 | 传递 | MIT OR Apache-2.0 | 未声明 |
| icu_collections | 2.1.1 | 传递 | Unicode-3.0 | 1.83 |
| icu_locale_core | 2.1.1 | 传递 | Unicode-3.0 | 1.83 |
| icu_normalizer | 2.1.1 | 传递 | Unicode-3.0 | 1.83 |
| icu_normalizer_data | 2.1.1 | 传递 | Unicode-3.0 | 1.83 |
| icu_properties | 2.1.2 | 传递 | Unicode-3.0 | 1.83 |
| icu_properties_data | 2.1.2 | 传递 | Unicode-3.0 | 1.83 |
| icu_provider | 2.1.1 | 传递 | Unicode-3.0 | 1.83 |
| idna | 1.1.0 | 传递 | MIT OR Apache-2.0 | 1.57 |
| idna_adapter | 1.2.1 | 传递 | Apache-2.0 OR MIT | 1.82 |
| indexmap | 2.14.2 | 传递 | Apache-2.0 OR MIT | 1.85 |
| inotify | 0.11.5 | 传递 | ISC | 1.70 |
| inotify-sys | 0.1.8 | 传递 | ISC | 未声明 |
| inout | 0.1.4 | 传递 | MIT OR Apache-2.0 | 1.56 |
| inout | 0.2.5 | 传递 | MIT OR Apache-2.0 | 1.85 |
| ip_network | 0.4.1 | 传递 | BSD-2-Clause | 未声明 |
| ip_network_table | 0.2.0 | 传递 | BSD-2-Clause | 未声明 |
| ip_network_table-deps-treebitmap | 0.5.0 | 传递 | MIT | 未声明 |
| ipconfig | 0.3.4 | 传递 | MIT/Apache-2.0 | 1.71 |
| ipnet | 2.12.2 | 直接（含开发） | MIT OR Apache-2.0 | 未声明 |
| is_terminal_polyfill | 1.70.2 | 传递 | MIT OR Apache-2.0 | 1.70.0 |
| itertools | 0.14.0 | 传递 | MIT OR Apache-2.0 | 1.63.0 |
| itoa | 1.0.18 | 传递 | MIT OR Apache-2.0 | 1.68 |
| jiff | 0.2.39 | 传递 | Unlicense OR MIT | 1.70 |
| jiff-core | 0.1.2 | 传递 | Unlicense OR MIT | 1.70 |
| jiff-static | 0.2.39 | 传递 | Unlicense OR MIT | 1.70 |
| jni | 0.22.4 | 传递 | MIT OR Apache-2.0 | 1.85.0 |
| jni-macros | 0.22.4 | 传递 | MIT OR Apache-2.0 | 未声明 |
| jni-sys | 0.4.1 | 传递 | MIT OR Apache-2.0 | 1.76.0 |
| jni-sys-macros | 0.4.1 | 传递 | MIT OR Apache-2.0 | 未声明 |
| jobserver | 0.1.35 | 传递 | MIT OR Apache-2.0 | 1.85 |
| js-sys | 0.3.107 | 传递 | MIT OR Apache-2.0 | 1.81 |
| keccak | 0.2.2 | 传递 | Apache-2.0 OR MIT | 1.85 |
| kem | 0.3.0 | 传递 | Apache-2.0 OR MIT | 1.85 |
| kqueue | 1.2.1 | 传递 | MIT | 未声明 |
| kqueue-sys | 1.1.2 | 传递 | MIT | 1.65 |
| lazy_static | 1.5.1 | 传递 | MIT OR Apache-2.0 | 未声明 |
| libc | 0.2.191 | 传递 | MIT OR Apache-2.0 | 1.65 |
| libm | 0.2.16 | 传递 | MIT | 1.63 |
| linux-raw-sys | 0.12.1 | 传递 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | 1.63 |
| litemap | 0.8.3 | 传递 | Unicode-3.0 | 1.82 |
| lock_api | 0.4.14 | 传递 | MIT OR Apache-2.0 | 1.71.0 |
| log | 0.4.35 | 传递 | MIT OR Apache-2.0 | 1.71.0 |
| lru-slab | 0.1.3 | 传递 | MIT OR Apache-2.0 OR Zlib | 未声明 |
| lru_time_cache | 0.11.11 | 传递 | MIT OR BSD-3-Clause | 未声明 |
| managed | 0.8.0 | 传递 | 0BSD | 未声明 |
| md-5 | 0.11.0 | 直接（含开发） | MIT OR Apache-2.0 | 1.85 |
| memchr | 2.8.3 | 传递 | Unlicense OR MIT | 1.61 |
| minimal-lexical | 0.2.1 | 传递 | MIT/Apache-2.0 | 未声明 |
| mio | 1.2.4 | 传递 | MIT | 1.71 |
| ml-kem | 0.3.4 | 直接（含开发） | Apache-2.0 OR MIT | 1.87 |
| module-lattice | 0.2.4 | 传递 | Apache-2.0 OR MIT | 1.87 |
| moka | 0.12.16 | 传递 | (MIT OR Apache-2.0) AND Apache-2.0 | 1.71.1 |
| ndk-context | 0.1.1 | 传递 | MIT OR Apache-2.0 | 未声明 |
| nix | 0.31.3 | 传递 | MIT | 1.69 |
| nom | 7.1.3 | 传递 | MIT | 1.48 |
| notify | 8.2.1 | 传递 | CC0-1.0 | 1.85 |
| notify-types | 2.2.0 | 传递 | MIT OR Apache-2.0 | 1.88 |
| nowhere | 3.3.0 | 直接（含开发） | GPL-3.0-only | 未声明 |
| nu-ansi-term | 0.50.3 | 传递 | MIT | 1.62.1 |
| num-bigint | 0.4.8 | 传递 | MIT OR Apache-2.0 | 1.60 |
| num-conv | 0.2.0 | 传递 | MIT OR Apache-2.0 | 1.57.0 |
| num-integer | 0.1.47 | 传递 | MIT OR Apache-2.0 | 1.31 |
| num-traits | 0.2.19 | 传递 | MIT OR Apache-2.0 | 1.60 |
| objc2-core-foundation | 0.3.2 | 传递 | Zlib OR Apache-2.0 OR MIT | 1.71 |
| objc2-core-services | 0.3.2 | 传递 | Zlib OR Apache-2.0 OR MIT | 1.71 |
| oid-registry | 0.8.1 | 传递 | MIT OR Apache-2.0 | 1.63 |
| once_cell | 1.21.4 | 传递 | MIT OR Apache-2.0 | 1.65 |
| once_cell_polyfill | 1.70.2 | 传递 | MIT OR Apache-2.0 | 1.70.0 |
| opaque-debug | 0.3.1 | 传递 | MIT OR Apache-2.0 | 未声明 |
| openssl-probe | 0.2.2 | 传递 | MIT OR Apache-2.0 | 1.60.0 |
| parking_lot | 0.12.5 | 传递 | MIT OR Apache-2.0 | 1.71 |
| parking_lot_core | 0.9.12 | 传递 | MIT OR Apache-2.0 | 1.71.0 |
| password-hash | 0.5.0 | 传递 | MIT OR Apache-2.0 | 1.60 |
| pem | 3.0.6 | 传递 | MIT | 1.60.0 |
| percent-encoding | 2.3.2 | 传递 | MIT OR Apache-2.0 | 1.51 |
| pin-project | 1.1.13 | 传递 | Apache-2.0 OR MIT | 1.71 |
| pin-project-internal | 1.1.13 | 传递 | Apache-2.0 OR MIT | 1.71 |
| pin-project-lite | 0.2.17 | 传递 | Apache-2.0 OR MIT | 1.37 |
| pkcs8 | 0.11.0 | 传递 | Apache-2.0 OR MIT | 1.85 |
| pkg-config | 0.3.34 | 传递 | MIT OR Apache-2.0 | 1.63 |
| poly1305 | 0.8.0 | 传递 | Apache-2.0 OR MIT | 1.56 |
| poly1305 | 0.9.1 | 传递 | Apache-2.0 OR MIT | 1.85 |
| polyval | 0.7.3 | 传递 | Apache-2.0 OR MIT | 1.85 |
| portable-atomic | 1.15.0 | 传递 | Apache-2.0 OR MIT | 1.34 |
| portable-atomic-util | 0.2.8 | 传递 | Apache-2.0 OR MIT | 1.36 |
| potential_utf | 0.1.6 | 传递 | Unicode-3.0 | 1.82 |
| powerfmt | 0.2.1 | 传递 | MIT OR Apache-2.0 | 1.79.0 |
| prefix-trie | 0.8.4 | 传递 | MIT OR Apache-2.0 | 1.71.1 |
| proc-macro2 | 1.0.107 | 传递 | MIT OR Apache-2.0 | 1.71 |
| prost | 0.14.4 | 直接（含开发） | Apache-2.0 | 1.85 |
| prost-derive | 0.14.4 | 传递 | Apache-2.0 | 1.85 |
| quinn | 0.11.11 | 直接（含开发） | MIT OR Apache-2.0 | 1.85 |
| quinn-proto | 0.11.19 | 直接（含开发） | MIT OR Apache-2.0 | 1.85 |
| quinn-udp | 0.5.16 | 传递 | MIT OR Apache-2.0 | 1.85 |
| quote | 1.0.47 | 传递 | MIT OR Apache-2.0 | 1.71 |
| r-efi | 6.0.0 | 传递 | MIT OR Apache-2.0 OR LGPL-2.1-or-later | 1.68 |
| rand | 0.10.3 | 传递 | MIT OR Apache-2.0 | 1.85 |
| rand_core | 0.10.1 | 传递 | MIT OR Apache-2.0 | 1.85 |
| rand_core | 0.6.4 | 传递 | MIT OR Apache-2.0 | 未声明 |
| rand_pcg | 0.10.2 | 传递 | MIT OR Apache-2.0 | 1.85 |
| rcgen | 0.13.2 | 直接（含开发） | MIT OR Apache-2.0 | 未声明 |
| rcgen | 0.14.10 | 直接（含开发） | MIT OR Apache-2.0 | 1.88 |
| redox_syscall | 0.5.18 | 传递 | MIT | 未声明 |
| regex | 1.13.1 | 传递 | MIT OR Apache-2.0 | 1.65 |
| regex-automata | 0.4.18 | 传递 | MIT OR Apache-2.0 | 1.65 |
| regex-syntax | 0.8.11 | 传递 | MIT OR Apache-2.0 | 1.65 |
| resolv-conf | 0.7.6 | 传递 | MIT OR Apache-2.0 | 1.61 |
| ring | 0.17.14 | 传递 | Apache-2.0 AND ISC | 1.66.0 |
| dubhe | 0.1.0 | 项目 | GPL-3.0-only | 1.91 |
| rustc-hash | 2.1.3 | 传递 | Apache-2.0 OR MIT | 1.77 |
| rustc_version | 0.4.1 | 传递 | MIT OR Apache-2.0 | 1.32 |
| rusticata-macros | 4.1.0 | 传递 | MIT/Apache-2.0 | 未声明 |
| rustix | 1.1.6 | 传递 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | 1.65 |
| rustls | 0.23.46 | 直接（含开发） | Apache-2.0 OR ISC OR MIT | 1.71 |
| rustls-native-certs | 0.8.5 | 传递 | Apache-2.0 OR ISC OR MIT | 1.71 |
| rustls-pki-types | 1.15.1 | 直接（含开发） | MIT OR Apache-2.0 | 1.60 |
| rustls-webpki | 0.103.16 | 传递 | ISC | 1.71 |
| rustversion | 1.0.23 | 传递 | MIT OR Apache-2.0 | 1.31 |
| ryu | 1.0.23 | 传递 | Apache-2.0 OR BSL-1.0 | 1.71 |
| same-file | 1.0.6 | 传递 | Unlicense/MIT | 未声明 |
| schannel | 0.1.30 | 传递 | MIT | 1.71.0 |
| scopeguard | 1.2.0 | 传递 | MIT OR Apache-2.0 | 未声明 |
| sealed | 0.7.0 | 传递 | MIT OR Apache-2.0 | 1.71.0 |
| security-framework | 3.7.0 | 传递 | MIT OR Apache-2.0 | 1.85 |
| security-framework-sys | 2.17.0 | 传递 | MIT OR Apache-2.0 | 1.70 |
| semver | 1.0.28 | 传递 | MIT OR Apache-2.0 | 1.68 |
| sendfd | 0.4.5 | 传递 | Apache-2.0 OR BSD-3-Clause | 未声明 |
| serde | 1.0.229 | 直接（含开发） | MIT OR Apache-2.0 | 1.56 |
| serde_core | 1.0.229 | 传递 | MIT OR Apache-2.0 | 1.56 |
| serde_derive | 1.0.229 | 传递 | MIT OR Apache-2.0 | 1.71 |
| serde_json | 1.0.154 | 直接（含开发） | MIT OR Apache-2.0 | 1.71 |
| serde_urlencoded | 0.7.1 | 传递 | MIT/Apache-2.0 | 未声明 |
| sha1 | 0.11.0 | 传递 | MIT OR Apache-2.0 | 1.85 |
| sha2 | 0.10.9 | 直接（含开发） | MIT OR Apache-2.0 | 未声明 |
| sha2 | 0.11.1 | 直接（含开发） | MIT OR Apache-2.0 | 1.88 |
| sha3 | 0.12.0 | 传递 | MIT OR Apache-2.0 | 1.85 |
| shadowsocks | 1.25.0 | 直接（含开发） | MIT | 1.91 |
| shadowsocks-crypto | 0.8.0 | 传递 | MIT | 1.85 |
| shake | 0.1.0 | 直接（含开发） | MIT OR Apache-2.0 | 1.85 |
| sharded-slab | 0.1.7 | 传递 | MIT | 1.42.0 |
| shlex | 2.0.1 | 传递 | MIT OR Apache-2.0 | 1.46.0 |
| signal-hook-registry | 1.4.8 | 传递 | MIT OR Apache-2.0 | 1.26 |
| simd_cesu8 | 1.2.0 | 传递 | Apache-2.0 OR MIT | 1.85.0 |
| simdutf8 | 0.1.5 | 传递 | MIT OR Apache-2.0 | 未声明 |
| siphasher | 1.0.4 | 传递 | MIT OR Apache-2.0 | 未声明 |
| slab | 0.4.12 | 传递 | MIT | 1.51 |
| smallvec | 1.16.4 | 传递 | MIT OR Apache-2.0 | 未声明 |
| smoltcp | 0.14.0 | 直接（含开发） | 0BSD | 1.91 |
| socket2 | 0.6.5 | 直接（含开发） | MIT OR Apache-2.0 | 1.70 |
| spin | 0.12.3 | 传递 | MIT | 1.71 |
| spki | 0.8.1 | 传递 | Apache-2.0 OR MIT | 1.85 |
| sponge-cursor | 0.1.0 | 传递 | MIT OR Apache-2.0 | 1.85 |
| stable_deref_trait | 1.2.1 | 传递 | MIT OR Apache-2.0 | 未声明 |
| strsim | 0.11.1 | 传递 | MIT | 1.56 |
| subtle | 2.6.1 | 直接（含开发） | BSD-3-Clause | 未声明 |
| symlink | 0.1.0 | 传递 | MIT/Apache-2.0 | 未声明 |
| syn | 2.0.119 | 传递 | MIT OR Apache-2.0 | 1.71 |
| syn | 3.0.9 | 传递 | MIT OR Apache-2.0 | 1.71 |
| synstructure | 0.13.2 | 传递 | MIT | 未声明 |
| synstructure | 0.14.0 | 传递 | MIT | 1.71 |
| system-configuration | 0.7.0 | 传递 | MIT OR Apache-2.0 | 1.64.0 |
| system-configuration-sys | 0.6.0 | 传递 | MIT OR Apache-2.0 | 未声明 |
| tagptr | 0.2.0 | 传递 | MIT/Apache-2.0 | 未声明 |
| tempfile | 3.27.0 | 直接（含开发） | MIT OR Apache-2.0 | 1.63 |
| thiserror | 2.0.21 | 传递 | MIT OR Apache-2.0 | 1.77 |
| thiserror-impl | 2.0.21 | 传递 | MIT OR Apache-2.0 | 1.77 |
| thread_local | 1.1.10 | 传递 | MIT OR Apache-2.0 | 1.63 |
| time | 0.3.47 | 传递 | MIT OR Apache-2.0 | 1.88.0 |
| time-core | 0.1.8 | 传递 | MIT OR Apache-2.0 | 1.88.0 |
| time-macros | 0.2.27 | 传递 | MIT OR Apache-2.0 | 1.88.0 |
| tinystr | 0.8.5 | 传递 | Unicode-3.0 | 1.82 |
| tinyvec | 1.13.3 | 传递 | Zlib OR Apache-2.0 OR MIT | 未声明 |
| tokio | 1.54.1 | 直接（含开发） | MIT | 1.85 |
| tokio-macros | 2.7.2 | 传递 | MIT | 1.71 |
| tokio-rustls | 0.26.6 | 直接（含开发） | MIT OR Apache-2.0 | 1.71 |
| tokio-tfo | 0.4.3 | 传递 | MIT | 未声明 |
| tokio-tungstenite | 0.30.0 | 直接（含开发） | MIT | 1.85 |
| tokio-util | 0.7.20 | 直接（含开发） | MIT | 1.85 |
| tracing | 0.1.44 | 直接（含开发） | MIT | 1.65.0 |
| tracing-appender | 0.2.5 | 直接（含开发） | MIT | 1.63.0 |
| tracing-attributes | 0.1.31 | 传递 | MIT | 1.65.0 |
| tracing-core | 0.1.36 | 传递 | MIT | 1.65.0 |
| tracing-log | 0.2.0 | 传递 | MIT | 1.56.0 |
| tracing-serde | 0.2.0 | 传递 | MIT | 1.63.0 |
| tracing-subscriber | 0.3.23 | 直接（含开发） | MIT | 1.65.0 |
| trait-variant | 0.1.3 | 传递 | MIT OR Apache-2.0 | 1.75 |
| tungstenite | 0.30.0 | 直接（含开发） | MIT OR Apache-2.0 | 1.85 |
| typenum | 1.20.1 | 传递 | MIT OR Apache-2.0 | 1.41.0 |
| unicode-ident | 1.0.27 | 传递 | (MIT OR Apache-2.0) AND Unicode-3.0 | 1.71 |
| universal-hash | 0.5.1 | 传递 | MIT OR Apache-2.0 | 1.56 |
| universal-hash | 0.6.1 | 传递 | MIT OR Apache-2.0 | 1.85 |
| untrusted | 0.7.1 | 传递 | ISC | 未声明 |
| untrusted | 0.9.0 | 传递 | ISC | 未声明 |
| url | 2.5.8 | 直接（含开发） | MIT OR Apache-2.0 | 1.63 |
| utf8_iter | 1.1.0 | 传递 | Apache-2.0 OR MIT | 1.83 |
| utf8parse | 0.2.2 | 传递 | Apache-2.0 OR MIT | 未声明 |
| utf_types | 1.0.0 | 传递 | Apache-2.0 OR MIT | 1.83 |
| uuid | 1.29.0 | 传递 | Apache-2.0 OR MIT | 1.89.0 |
| valuable | 0.1.1 | 传递 | MIT | 1.56 |
| version_check | 0.9.5 | 传递 | MIT/Apache-2.0 | 未声明 |
| walkdir | 2.5.0 | 传递 | Unlicense/MIT | 未声明 |
| wasi | 0.11.1+wasi-snapshot-preview1 | 传递 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | 未声明 |
| wasm-bindgen | 0.2.130 | 传递 | MIT OR Apache-2.0 | 1.81 |
| wasm-bindgen-macro | 0.2.130 | 传递 | MIT OR Apache-2.0 | 1.81 |
| wasm-bindgen-macro-support | 0.2.130 | 传递 | MIT OR Apache-2.0 | 1.81 |
| wasm-bindgen-shared | 0.2.130 | 传递 | MIT OR Apache-2.0 | 1.81 |
| web-time | 1.1.0 | 传递 | MIT OR Apache-2.0 | 1.60 |
| widestring | 1.2.1 | 传递 | MIT OR Apache-2.0 | 1.58 |
| winapi-util | 0.1.11 | 传递 | Unlicense OR MIT | 未声明 |
| windows-core | 0.62.2 | 传递 | MIT OR Apache-2.0 | 1.82 |
| windows-implement | 0.60.2 | 传递 | MIT OR Apache-2.0 | 1.74 |
| windows-interface | 0.59.3 | 传递 | MIT OR Apache-2.0 | 1.74 |
| windows-link | 0.2.1 | 传递 | MIT OR Apache-2.0 | 1.71 |
| windows-registry | 0.6.1 | 传递 | MIT OR Apache-2.0 | 1.82 |
| windows-result | 0.4.1 | 传递 | MIT OR Apache-2.0 | 1.82 |
| windows-strings | 0.5.1 | 传递 | MIT OR Apache-2.0 | 1.82 |
| windows-sys | 0.52.0 | 传递 | MIT OR Apache-2.0 | 1.56 |
| windows-sys | 0.60.2 | 传递 | MIT OR Apache-2.0 | 1.60 |
| windows-sys | 0.61.2 | 传递 | MIT OR Apache-2.0 | 1.71 |
| windows-targets | 0.52.6 | 传递 | MIT OR Apache-2.0 | 1.56 |
| windows-targets | 0.53.5 | 传递 | MIT OR Apache-2.0 | 1.60 |
| windows_aarch64_gnullvm | 0.52.6 | 传递 | MIT OR Apache-2.0 | 1.56 |
| windows_aarch64_gnullvm | 0.53.1 | 传递 | MIT OR Apache-2.0 | 1.60 |
| windows_aarch64_msvc | 0.52.6 | 传递 | MIT OR Apache-2.0 | 1.56 |
| windows_aarch64_msvc | 0.53.1 | 传递 | MIT OR Apache-2.0 | 1.60 |
| windows_i686_gnu | 0.52.6 | 传递 | MIT OR Apache-2.0 | 1.56 |
| windows_i686_gnu | 0.53.1 | 传递 | MIT OR Apache-2.0 | 1.60 |
| windows_i686_gnullvm | 0.52.6 | 传递 | MIT OR Apache-2.0 | 1.56 |
| windows_i686_gnullvm | 0.53.1 | 传递 | MIT OR Apache-2.0 | 1.60 |
| windows_i686_msvc | 0.52.6 | 传递 | MIT OR Apache-2.0 | 1.56 |
| windows_i686_msvc | 0.53.1 | 传递 | MIT OR Apache-2.0 | 1.60 |
| windows_x86_64_gnu | 0.52.6 | 传递 | MIT OR Apache-2.0 | 1.56 |
| windows_x86_64_gnu | 0.53.1 | 传递 | MIT OR Apache-2.0 | 1.60 |
| windows_x86_64_gnullvm | 0.52.6 | 传递 | MIT OR Apache-2.0 | 1.56 |
| windows_x86_64_gnullvm | 0.53.1 | 传递 | MIT OR Apache-2.0 | 1.60 |
| windows_x86_64_msvc | 0.52.6 | 传递 | MIT OR Apache-2.0 | 1.56 |
| windows_x86_64_msvc | 0.53.1 | 传递 | MIT OR Apache-2.0 | 1.60 |
| writeable | 0.6.4 | 传递 | Unicode-3.0 | 1.82 |
| x25519-dalek | 2.0.1 | 传递 | BSD-3-Clause | 1.60 |
| x509-parser | 0.18.1 | 直接（含开发） | MIT OR Apache-2.0 | 1.67.1 |
| yasna | 0.5.2 | 直接（含开发） | MIT OR Apache-2.0 | 未声明 |
| yasna | 0.6.0 | 直接（含开发） | MIT OR Apache-2.0 | 1.60 |
| yoke | 0.8.4 | 传递 | Unicode-3.0 | 1.82 |
| yoke-derive | 0.8.4 | 传递 | Unicode-3.0 | 1.82 |
| zerofrom | 0.1.8 | 传递 | Unicode-3.0 | 1.71.1 |
| zerofrom-derive | 0.1.8 | 传递 | Unicode-3.0 | 1.71.1 |
| zeroize | 1.9.1 | 传递 | Apache-2.0 OR MIT | 1.85 |
| zeroize_derive | 1.5.0 | 传递 | Apache-2.0 OR MIT | 1.85 |
| zerotrie | 0.2.5 | 传递 | Unicode-3.0 | 1.82 |
| zerovec | 0.11.9 | 传递 | Unicode-3.0 | 1.83 |
| zerovec-derive | 0.11.7 | 传递 | Unicode-3.0 | 1.83 |
| zmij | 1.0.23 | 传递 | MIT | 1.71 |

首批协议依据：[SOCKS5 RFC 1928](https://www.rfc-editor.org/rfc/rfc1928)、[用户名密码 RFC 1929](https://www.rfc-editor.org/rfc/rfc1929)、[Trojan 协议说明](https://trojan-gfw.github.io/trojan/protocol)。上游固定提交另见 `reference-clients.md`。
