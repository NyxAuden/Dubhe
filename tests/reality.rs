mod common;
#[path = "common/reality.rs"]
mod reality_peer;

// 业务集成场景由 main 在生产入口 ready 后补充；独立客户端/target 的自测位于 reality_peer。
