use anyhow::{anyhow, Context as _, Result};
use clap::{load_yaml, App, ArgMatches};
use config::Node;
use node::weighted_test::{self, Options, Shutdown};
use std::{
    net::{SocketAddr, SocketAddrV4},
    path::PathBuf,
    time::Duration,
};
use tokio::sync::{mpsc::channel, oneshot};

fn weighted_options(args: &ArgMatches<'_>) -> Result<Options> {
    Ok(Options {
        absent: args
            .value_of("test_absent")
            .unwrap()
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| s.trim().parse())
            .collect::<std::result::Result<_, _>>()?,
        result_file: args.value_of("test_result").map(PathBuf::from),
        timeout: Duration::from_secs(args.value_of("test_timeout").unwrap().parse()?),
        bits: args.value_of("test_bits").unwrap().parse()?,
        payload_bytes: args.value_of("test_payload_bytes").unwrap().parse()?,
        block_bytes: args.value_of("test_block_bytes").unwrap().parse()?,
    })
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let yaml = load_yaml!("cli.yml");
    let args = App::from_yaml(yaml).get_matches();
    let level = match args.occurrences_of("debug") {
        0 => log::LevelFilter::Info,
        1 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    };
    if let Err(error) = node::logging::init(level) {
        log::error!("Failed to initialize node logging: {}", error);
        return std::process::ExitCode::FAILURE;
    }
    match run(&args).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            log::error!("Node failed: {:#}", error);
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run(args: &ArgMatches<'_>) -> Result<()> {
    let config_path = args.value_of("config").unwrap();
    let protocol = args.value_of("protocol").unwrap();
    let filename = config_path.to_owned();
    let mut config = match std::path::Path::new(config_path)
        .extension()
        .and_then(|e| e.to_str())
    {
        Some("json") => Node::from_json(filename),
        Some("dat") => Node::from_bin(filename),
        Some("toml") => Node::from_toml(filename),
        Some("yaml" | "yml") => Node::from_yaml(filename),
        _ => return Err(anyhow!("unsupported configuration file extension")),
    };
    log::info!(
        "Node {}: starting protocol {} (pid={})",
        config.id,
        protocol,
        std::process::id()
    );
    if let Some(filename) = args.value_of("ip") {
        config.update_config(util::io::file_to_ips(filename.to_owned()));
    }
    match protocol {
        "wra" => weighted_test::wra(config, weighted_options(&args)?).await,
        "wavid" => weighted_test::wavid(config, weighted_options(&args)?).await,
        "wrbc" => weighted_test::wrbc(config, weighted_options(&args)?).await,
        "wgather" => weighted_test::wgather(config, weighted_options(&args)?).await,
        "wbinaa" => weighted_test::wbinaa(config, weighted_options(&args)?).await,
        "ctrbc" => {
            config.validate()?;
            let mut shutdown = Shutdown::new()?;
            let (exit, statuses) = spawn(config).await;
            let exit = exit.context("start CTRBC")?;
            // Retain successful child shutdown handles until service shutdown.
            let children = statuses.into_iter().collect::<Result<Vec<_>>>()?;
            shutdown.wait().await?;
            log::info!("CTRBC: received termination signal; shutting down");
            let _ = exit.send(());
            for child in children {
                let _ = child.send(());
            }
            tokio::task::yield_now().await;
            Ok(())
        }
        _ => Err(anyhow!("unsupported protocol: {}", protocol)),
    }
}

pub fn to_socket_address(ip_str: &str, port: u16) -> SocketAddr {
    SocketAddrV4::new(ip_str.parse().unwrap(), port).into()
}

pub async fn spawn(
    config: Node,
) -> (
    Result<oneshot::Sender<()>>,
    Vec<Result<oneshot::Sender<()>>>,
) {
    let (input, requests) = channel(10000);
    let (output, mut events) = channel(10000);
    let exit = match ctrbc::Context::spawn(config, requests, output, false) {
        Ok(exit) => exit,
        Err(error) => return (Err(error), vec![]),
    };
    if input.send(Vec::new()).await.is_err() {
        return (Err(anyhow!("CTRBC request channel closed")), vec![]);
    }
    tokio::spawn(async move {
        // Keep the existing request channel alive, and consume outputs until shutdown.
        let _input = input;
        while let Some(event) = events.recv().await {
            log::debug!("CTRBC output: {:?}", event);
        }
    });
    (Ok(exit), vec![])
}
