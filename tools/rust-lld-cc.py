#!/usr/bin/env python3
"""把 cc 风格的链接调用转交给 Rust 自带的 rust-lld（GNU flavor）。

Rust 的 x86_64-unknown-linux-musl 会传 `-static-pie`，而 macOS 上的系统 cc
不支持；rust-lld 支持。这里只做三件事：
1. 包装成 `rust-lld -flavor gnu`；
2. 丢掉与 ELF 目标无关的 Darwin/cc 参数（-m64、-march=*、-mmacosx-*）；
3. 拆开 `-Wl,` 前缀。

不做编译：只用于最终链接。编译 C/汇编仍走 zig-cc-musl.py。
"""
import os
import sys

LLD = ("/Users/ice/.rustup/toolchains/stable-aarch64-apple-darwin/lib/rustlib/"
       "aarch64-apple-darwin/bin/rust-lld")

DROP_EXACT = {"-m64", "-m32", "-nostartfiles", "-nodefaultlibs"}
DROP_PREFIX = ("-march=", "-mmacosx-", "-isysroot", "-arch")

args = []
skip_next = False
for arg in sys.argv[1:]:
    if skip_next:
        skip_next = False
        continue
    if arg in DROP_EXACT:
        continue
    if arg.startswith(DROP_PREFIX):
        # -isysroot / -arch 带独立值
        if arg in ("-isysroot", "-arch"):
            skip_next = True
        continue
    if arg.startswith("-Wl,"):
        args.extend(arg[4:].split(","))
        continue
    args.append(arg)

# aws-lc 的 C 代码引用 UBSan 钩子，而 Zig 构建不会链接 libubsan。
# 追加一个空实现的桩对象满足链接；这些钩子只在触发未定义行为时被调用。
args.append("/tmp/ubsan_stub.o")

os.execv(LLD, [LLD, "-flavor", "gnu", *args])
