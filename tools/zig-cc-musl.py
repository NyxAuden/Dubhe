#!/usr/bin/env python3
"""编译 C / 汇编源（ring、aws-lc-sys 的 build.rs 用），不参与最终链接。

Rust 的 x86_64-unknown-linux-musl 是自包含 target：启动文件与 musl libc 都在
`$SYSROOT/lib/rustlib/x86_64-unknown-linux-musl/lib/self-contained/`，最终链接
由 rust-lld 完成，不需要外部链接器。Zig 在这里只把 C/汇编编译成 .o。

需要处理三处 Zig 与 GCC 的差异：
1. target triple 命名：Rust 用 x86_64-unknown-linux-musl，Zig 用 x86_64-linux-musl。
2. `-march=x86-64`：Zig 只接受具体 CPU 名（baseline/x86_64_v2…），
   统一映射到 `-mcpu=baseline` 保持最广兼容。
3. 链接请求：直接拒绝，避免 Zig 注入自己的 crt1.o 与 Rust 的 rcrt1.o 冲突。
"""
import os
import sys

ZIG = "/opt/homebrew/Cellar/zig/0.17.1/bin/zig"
RUST_TRIPLE = "x86_64-unknown-linux-musl"
ZIG_TARGET = "x86_64-linux-musl"

raw = sys.argv[1:]

if "-c" not in raw:
    sys.stderr.write(
        "zig-cc-musl: refusing to link; Rust's musl target is self-contained "
        "and links with rust-lld. Only set CC_*/CXX_*, not the cargo linker.\n"
    )
    sys.exit(1)

args = []
for arg in raw:
    if arg in (f"--target={RUST_TRIPLE}", RUST_TRIPLE):
        continue
    if arg.startswith("-march="):
        # Zig 不认 x86-64 / x86_64 这类写法，用 baseline 保持通用。
        args.append("-mcpu=baseline")
        continue
    if arg == "-m64":
        # Zig 由 --target 决定位数，-m64 会与它重复。
        continue
    args.append(arg)

os.execv(ZIG, [ZIG, "cc", f"--target={ZIG_TARGET}", *args])
