# 多阶段构建：产物只含二进制与 CA，不带编译工具链。
# aws-lc-rs 需要 C/汇编工具链，builder 阶段显式安装。
FROM rust:1.91-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake nasm \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .
RUN cargo build --locked --release --bin dubhe

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --home /nonexistent --shell /usr/sbin/nologin dubhe \
    && install -d -o root -g dubhe -m 0750 /etc/dubhe

COPY --from=builder /src/target/release/dubhe /usr/local/bin/dubhe

USER dubhe
EXPOSE 1080/tcp

ENTRYPOINT ["/usr/local/bin/dubhe"]
CMD ["run", "-c", "/etc/dubhe/config.json"]
