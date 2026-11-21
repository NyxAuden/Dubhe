use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
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
    // 协议库原生日志可能包含EIH/身份哈希；只保留内核的脱敏、限速错误分类。
    let filter = tracing_subscriber::filter::Targets::new()
        .with_default(tracing::Level::INFO)
        .with_target("shadowsocks", tracing::level_filters::LevelFilter::OFF);
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
            std::fs::create_dir_all(&output)?;
            for target in targets {
                let value = dubhe::export::export(target, &nodes, &mut report)?;
                let name = format!("{}.json", target.file_name());
                let path = output.join(&name);
                std::fs::write(&path, serde_json::to_string_pretty(&value)? + "\n")?;
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
                Some(path) => std::fs::write(&path, rendered + "\n")
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
fn same_config(left: &Config, right: &Config) -> bool {
    match (serde_json::to_value(left), serde_json::to_value(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
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
    let server = Server::bind(config.clone()).await?;
    let mut reload = server.reload_handle();
    let mut hot = server.hot_reload_handle();
    let mut running = Box::pin(server.run(stop.clone()));
    loop {
        tokio::select! {
            result = &mut running => return result,
            _ = interrupt.recv() => {}
            _ = terminate.recv() => {}
            _ = hangup.recv() => {
                let new_config = match read_config(path.clone()) {
                    Ok(config) => config,
                    Err(error) => {
                        tracing::error!(event = "reload", reason = %error);
                        continue;
                    }
                };
                if let Err(error) = Server::check(&new_config) {
                    tracing::error!(event = "reload", reason = %error);
                    continue;
                }
                if same_config(&config, &new_config) {
                    match reload.reload() {
                        Ok(count) => {
                            tracing::info!(event = "reload_tls", inbounds = count);
                        }
                        Err(error) => {
                            tracing::error!(event = "reload_tls", reason = %error);
                        }
                    }
                    continue;
                }
                match hot.reload(&new_config) {
                    Ok(true) => {
                        config = new_config;
                        tracing::info!(event = "reload_hot");
                        continue;
                    }
                    Ok(false) => {}
                    Err(error) => {
                        tracing::error!(event = "reload_hot", reason = %error);
                        continue;
                    }
                }
                stop.cancel();
                if let Err(error) = (&mut running).await {
                    tracing::error!(event = "reload_stop", reason = %error);
                }
                let server = match Server::bind(new_config.clone()).await {
                    Ok(server) => {
                        config = new_config;
                        server
                    }
                    Err(error) => {
                        tracing::error!(event = "reload_bind", reason = %error);
                        Server::bind(config.clone()).await?
                    }
                };
                reload = server.reload_handle();
                hot = server.hot_reload_handle();
                stop = CancellationToken::new();
                running = Box::pin(server.run(stop.clone()));
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
