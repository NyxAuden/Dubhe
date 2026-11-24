use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use dubhe::apply::{ApplyErrorCode, ApplyMode, ApplyResult, ApplyState};
use dubhe::{Config, Server};
use tokio_util::sync::CancellationToken;

#[derive(Parser)]
#[command(version, about = "独立服务端代理内核")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Check {
        #[arg(short, long)]
        config: PathBuf,
    },
    Run {
        #[arg(short, long)]
        config: PathBuf,
    },
    /// 从 dubhe 服务端配置生成客户端配置（xray / sing-box / mihomo / anywhere）。
    Export {
        /// 目标格式；可用 `xray`、`sing-box`、`mihomo`、`anywhere`，或用 `all` 一次输出四份。
        #[arg(long, default_value = "all")]
        to: String,
        /// dubhe 服务端配置。
        #[arg(short, long)]
        config: PathBuf,
        /// 客户端要连接的服务器地址（配置里通常是 0.0.0.0，不能直接用）。
        #[arg(long)]
        host: String,
        /// 输出目录；每个目标格式写一个文件。
        #[arg(short, long, default_value = "export")]
        output: PathBuf,
    },
    /// 把上游内核的配置一次性转换成 dubhe 配置。
    Convert {
        /// 来源格式；当前只支持 xray。
        #[arg(long, default_value = "xray")]
        from: String,
        #[arg(short, long)]
        input: PathBuf,
        /// 输出路径；省略时写到 stdout。
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// 带 TLS 的出站必须显式给出信任锚 PEM。
        #[arg(long)]
        ca_file: Option<PathBuf>,
        /// 把跳过的字段与警告写到该文件；省略时写到 stderr。
        #[arg(long)]
        report: Option<PathBuf>,
    },
    Version,
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let (writer, _guard) = tracing_appender::non_blocking::NonBlockingBuilder::default()
        .buffered_lines_limit(1024)
        .lossy(true)
        .finish(std::io::stderr());
    use tracing_subscriber::{Layer, prelude::*};
    // 日志级别由 `DUBHE_LOG` 控制（语法同 `RUST_LOG`，例如
    // `DUBHE_LOG=debug` 或 `DUBHE_LOG=dubhe=trace,quinn=warn`）。
    //
    // 为什么不用 `RUST_LOG`：那是 reqwest/rustls 等第三方库的约定，多个
    // 依赖都会读它，容易互相干扰；用一个项目自己的变量更可控。
    //
    // 未设置时保持 INFO，与历史行为一致。shadowsocks 一律关闭：协议库的
    // 原生日志可能包含 EIH/身份哈希。
    let filter = match std::env::var("DUBHE_LOG") {
        Ok(value) if !value.trim().is_empty() => {
            tracing_subscriber::filter::EnvFilter::try_new(&value)
                .unwrap_or_else(|error| {
                    eprintln!("DUBHE_LOG 无效（{error}），回退到 info");
                    tracing_subscriber::filter::EnvFilter::new("info")
                })
                .add_directive("shadowsocks=off".parse().expect("静态指令"))
        }
        _ => tracing_subscriber::filter::EnvFilter::new("info")
            .add_directive("shadowsocks=off".parse().expect("静态指令")),
    };
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_writer(writer)
                .with_filter(filter),
        )
        .init();
    if let Err(error) = execute(Cli::parse()).await {
        // 下层错误只提供脱敏分类，不打印配置原文或协议载荷。
        tracing::error!(event="fatal", reason=%error);
        return std::process::ExitCode::FAILURE;
    }
    std::process::ExitCode::SUCCESS
}
async fn execute(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Version => println!("dubhe {}", env!("CARGO_PKG_VERSION")),
        Command::Check { config } => {
            let config = read_config(config)?;
            Server::check(&config)?;
            println!("配置检查通过");
        }
        Command::Export {
            to,
            config,
            host,
            output,
        } => {
            let config = read_config(config)?;
            Server::check(&config)?;
            if host.trim().is_empty() {
                return Err(anyhow::anyhow!("--host 不得为空"));
            }
            let targets: Vec<dubhe::export::Target> = if to == "all" {
                vec![
                    dubhe::export::Target::Xray,
                    dubhe::export::Target::SingBox,
                    dubhe::export::Target::Mihomo,
                    dubhe::export::Target::Anywhere,
                ]
            } else {
                vec![dubhe::export::Target::parse(&to)?]
            };
            let mut report = dubhe::export::ExportReport::default();
            let nodes = dubhe::export::nodes(&config, host.trim(), &mut report);
            if nodes.is_empty() {
                // 原因必须先打出来，否则用户只看到一句「没有可导出」。
                if !report.notes.is_empty() {
                    eprintln!("{}", report.notes.join("\n"));
                }
                return Err(anyhow::anyhow!("配置里没有可导出的入站"));
            }
            // 先在内存里生成全部目标，任何一个目标没有可用节点就整体失败：
            // `--to all` 不能留下半套文件，更不能把纯直连配置冒充成导出结果。
            let mut rendered = Vec::with_capacity(targets.len());
            for target in targets {
                // 失败时也要把跳过原因打出来，否则用户只看到「没有可用节点」。
                let value = match dubhe::export::export(target, &nodes, &mut report) {
                    Ok(value) => value,
                    Err(error) => {
                        if !report.notes.is_empty() {
                            eprintln!("{}", report.notes.join("\n"));
                        }
                        return Err(error);
                    }
                };
                rendered.push((target, serde_json::to_string_pretty(&value)? + "\n"));
            }
            std::fs::create_dir_all(&output)?;
            for (target, text) in rendered {
                let path = output.join(format!("{}.json", target.file_name()));
                write_private(&path, &text)?;
                println!("{}", path.display());
            }
            if !report.notes.is_empty() {
                eprintln!("{}", report.notes.join("\n"));
            }
        }
        Command::Convert {
            from,
            input,
            output,
            ca_file,
            report: report_path,
        } => {
            let text =
                std::fs::read_to_string(&input).map_err(|_| anyhow::anyhow!("转换输入不可读取"))?;
            let ca_file = ca_file
                .map(|path| {
                    path.to_str()
                        .map(str::to_owned)
                        .ok_or_else(|| anyhow::anyhow!("--ca-file 必须是有效 UTF-8 路径"))
                })
                .transpose()?;
            let converted = match from.as_str() {
                "xray" => dubhe::convert::from_xray(&text, ca_file.as_deref())?,
                other => {
                    return Err(anyhow::anyhow!(
                        "暂不支持的来源格式 {other}（当前仅支持 xray）"
                    ));
                }
            };
            let rendered = serde_json::to_string_pretty(&converted.json)?;
            let report = converted.report;
            match output {
                Some(path) => write_private(&path, &(rendered + "\n"))
                    .map_err(|_| anyhow::anyhow!("转换输出不可写入"))?,
                None => println!("{rendered}"),
            }
            if !report.notes.is_empty() {
                let text = report.notes.join("\n") + "\n";
                match report_path {
                    Some(path) => std::fs::write(&path, text)
                        .map_err(|_| anyhow::anyhow!("转换报告不可写入"))?,
                    None => eprint!("{text}"),
                }
            }
        }
        Command::Run { config } => {
            let path = config;
            let config = read_config(path.clone())?;
            run(path, config).await?;
        }
    }
    Ok(())
}
/// 配置内容比较；序列化失败按“已变化”处理，走完整重启。
#[cfg(unix)]
/// 导出/转换结果里有 UUID、密码与 REALITY 私钥，必须 0600。
///
/// 先写同目录的临时文件（创建即 0600），再原子替换目标：
/// - 已有 0644 文件不会在写入期间先被截断、又以旧权限可读；
/// - 中途失败时旧文件保持完整，不会留下半份配置。
///
/// 目标是符号链接时替换链接本身，不跟随写入（避免改写链接指向的文件）。
fn write_private(path: &std::path::Path, text: &str) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let name = path.file_name().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "输出路径缺少文件名")
        })?;
        // 独占创建：固定名字 + create(true) 会跟随已有对象（包括链接），
        // 在共享可写目录里可能覆盖别人的文件。用 pid + 纳秒做候选，撞上就换。
        let mut temp = path.to_path_buf();
        let mut file = None;
        for _ in 0..16 {
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|value| value.as_nanos())
                .unwrap_or_default();
            temp = path.with_file_name(format!(
                ".{}.{}.{}.tmp",
                name.to_string_lossy(),
                std::process::id(),
                stamp
            ));
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temp)
            {
                Ok(opened) => {
                    file = Some(opened);
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        let Some(mut file) = file else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "无法创建独占临时文件",
            ));
        };
        let written = (|| -> std::io::Result<()> {
            file.write_all(text.as_bytes())?;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            file.sync_all()?;
            std::fs::rename(&temp, path)
        })();
        if written.is_err() {
            let _ = std::fs::remove_file(&temp);
        }
        written
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, text)
    }
}

fn same_config(left: &Config, right: &Config) -> bool {
    match (serde_json::to_value(left), serde_json::to_value(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

/// 除 `deployment_id` 外业务配置是否完全相同。
///
/// 面板换标签但没改内容时走元数据路径：接受新标签，不做无谓的重绑定。
fn same_business_config(left: &Config, right: &Config) -> bool {
    let business = |config: &Config| {
        let mut value = serde_json::to_value(config).ok()?;
        if let Some(object) = value.as_object_mut() {
            object.remove("deployment_id");
        }
        Some(value)
    };
    matches!((business(left), business(right)), (Some(left), Some(right)) if left == right)
}

/// 读取重载候选，区分「读不到」与「配置无效」——两者要给面板不同的错误码，
/// 不能都归成一次普通失败。
enum Candidate {
    Unreadable,
    Invalid,
    // `Config` 很大，装箱避免把枚举体撑到配置大小。
    Valid(Box<Config>),
}

fn read_candidate(path: &PathBuf) -> Candidate {
    match std::fs::read_to_string(path) {
        Err(_) => Candidate::Unreadable,
        Ok(input) => match Config::from_json(&input) {
            Ok(config) => Candidate::Valid(Box::new(config)),
            Err(_) => Candidate::Invalid,
        },
    }
}

#[cfg(unix)]
async fn run(path: PathBuf, mut config: Config) -> Result<()> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    // SIGHUP：配置未变时只替换 TCP/TLS 入口的证书，不重启监听，现有连接
    // 保持使用握手时的证书；配置变化时仍需完整重启，旧实例完全停止后才
    // 绑定新实例。新配置校验失败时保持旧实例不变。
    let mut hangup = signal(SignalKind::hangup())?;
    let mut stop = CancellationToken::new();
    // 状态句柄属于进程，不属于某个 Server 实例：重建与回退必须复用同一个
    // Arc，否则面板看到的 `instance_id` 会变，无法确认是自己那次提交。
    let apply = ApplyState::new(config.deployment_id.clone());
    let server = Server::bind(config.clone())
        .await?
        .with_apply_state(apply.clone());
    let mut reload = server.reload_handle();
    let mut hot = server.hot_reload_handle();
    let mut running = Box::pin(server.run(stop.clone()));
    loop {
        tokio::select! {
            result = &mut running => return result,
            _ = interrupt.recv() => {}
            _ = terminate.recv() => {}
            _ = hangup.recv() => {
                let attempt = apply.begin();
                let new_config = match read_candidate(&path) {
                    Candidate::Valid(config) => *config,
                    Candidate::Unreadable => {
                        tracing::error!(event = "reload", reason = "配置文件不可读取");
                        apply.finish(attempt, ApplyMode::Validate, ApplyResult::Rejected,
                            Some(ApplyErrorCode::ConfigUnreadable), None);
                        continue;
                    }
                    Candidate::Invalid => {
                        tracing::error!(event = "reload", reason = "配置无效");
                        apply.finish(attempt, ApplyMode::Validate, ApplyResult::Rejected,
                            Some(ApplyErrorCode::ConfigInvalid), None);
                        continue;
                    }
                };
                apply.set_candidate(attempt, new_config.deployment_id.clone());
                if let Err(error) = Server::check(&new_config) {
                    tracing::error!(event = "reload", reason = %error);
                    apply.finish(attempt, ApplyMode::Validate, ApplyResult::Rejected,
                        Some(ApplyErrorCode::ConfigInvalid), None);
                    continue;
                }
                // 复用当前标签却改了业务内容：拒绝，否则一个标签会指向两份配置。
                if new_config.deployment_id.is_some()
                    && new_config.deployment_id == config.deployment_id
                    && !same_business_config(&config, &new_config)
                {
                    tracing::error!(event = "reload", reason = "deployment_id 被复用");
                    apply.finish(attempt, ApplyMode::Validate, ApplyResult::Rejected,
                        Some(ApplyErrorCode::DeploymentIdReused), None);
                    continue;
                }
                if same_config(&config, &new_config) {
                    let outcome = reload.reload();
                    match &outcome {
                        Ok(count) if *count > 0 => {
                            tracing::info!(event = "reload_tls", inbounds = count);
                            // 单纯轮换证书不推进配置代数。
                            apply.finish(attempt, ApplyMode::Tls, ApplyResult::Applied, None, None);
                        }
                        Ok(_) => {
                            tracing::info!(event = "reload_tls", inbounds = 0);
                            apply.finish(attempt, ApplyMode::Tls, ApplyResult::Noop, None, None);
                        }
                        Err(error) => {
                            tracing::error!(event = "reload_tls", reason = %error);
                            apply.finish(attempt, ApplyMode::Tls, ApplyResult::Rejected,
                                Some(ApplyErrorCode::TlsReloadFailed), None);
                        }
                    }
                    continue;
                }
                if same_business_config(&config, &new_config) {
                    // 只换了部署标签：接受标签并推进一代，不做无谓的重绑定。
                    config = new_config;
                    tracing::info!(event = "reload_metadata");
                    apply.finish(attempt, ApplyMode::Metadata, ApplyResult::Applied, None,
                        config.deployment_id.clone());
                    continue;
                }
                match hot.reload(&new_config) {
                    Ok(true) => {
                        let deployment_id = new_config.deployment_id.clone();
                        config = new_config;
                        tracing::info!(event = "reload_hot");
                        apply.finish(attempt, ApplyMode::Hot, ApplyResult::Applied, None,
                            deployment_id);
                        continue;
                    }
                    // 需要重建：不是失败，也不是成功，先标记重绑进行中。
                    Ok(false) => apply.set_mode(attempt, ApplyMode::Rebind),
                    Err(error) => {
                        tracing::error!(event = "reload_hot", reason = %error);
                        apply.finish(attempt, ApplyMode::Hot, ApplyResult::Rejected,
                            Some(ApplyErrorCode::HotApplyFailed), None);
                        continue;
                    }
                }
                stop.cancel();
                if let Err(error) = (&mut running).await {
                    tracing::error!(event = "reload_stop", reason = %error);
                }
                let (next, outcome) = match Server::bind(new_config.clone()).await {
                    Ok(server) => {
                        let deployment_id = new_config.deployment_id.clone();
                        config = new_config;
                        (server, (ApplyResult::Applied, None, deployment_id))
                    }
                    Err(error) => {
                        tracing::error!(event = "reload_bind", reason = %error);
                        // 回退只恢复旧**配置**，不恢复旧会话与计数器。
                        let server = Server::bind(config.clone()).await?;
                        (
                            server,
                            (
                                ApplyResult::RolledBack,
                                Some(ApplyErrorCode::CandidateBindFailed),
                                config.deployment_id.clone(),
                            ),
                        )
                    }
                };
                // 终态等新监听 ready 再提交，避免把「拿到 socket」报成「已启动」。
                let (result, error_code, deployment_id) = outcome;
                apply.stage_commit(attempt, ApplyMode::Rebind, result, error_code, deployment_id);
                reload = next.reload_handle();
                hot = next.hot_reload_handle();
                stop = CancellationToken::new();
                running = Box::pin(next.with_apply_state(apply.clone()).run(stop.clone()));
                continue;
            }
        }
        stop.cancel();
        running.await?;
        return Ok(());
    }
}

#[cfg(not(unix))]
async fn run(_path: PathBuf, config: Config) -> Result<()> {
    let stop = CancellationToken::new();
    let mut running = Box::pin(Server::bind(config).await?.run(stop.clone()));
    tokio::select! {
        result = &mut running => result,
        _ = tokio::signal::ctrl_c() => {
            stop.cancel();
            (&mut running).await
        }
    }
}

fn read_config(path: PathBuf) -> Result<Config> {
    let input = std::fs::read_to_string(path).map_err(|_| anyhow::anyhow!("配置文件不可读取"))?;
    Config::from_json(&input)
}
