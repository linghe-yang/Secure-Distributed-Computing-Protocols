//! One physical node per process for local distributed protocol tests.
//! The supplied inputs and local timeout belong to the harness, not the protocols.
use anyhow::{anyhow, ensure, Context as _, Result};
use config::Node;
use serde_json::{json, Value};
use std::{path::PathBuf, time::Duration};
use tokio::sync::{
    mpsc::{channel, Receiver, Sender},
    oneshot,
};
use types::InstanceId;

pub struct Options {
    pub absent: Vec<usize>,
    pub result_file: Option<PathBuf>,
    pub timeout: Duration,
    pub bits: u32,
    pub payload_bytes: usize,
}
impl Options {
    pub fn active(&self, config: &Node) -> Result<Vec<usize>> {
        config.validate_weighted()?;
        ensure!(!self.timeout.is_zero(), "test timeout must be positive");
        ensure!(
            self.bits <= wbinaa::MAX_ROUNDS,
            "test bits exceed BinAA resource limit"
        );
        ensure!(
            self.payload_bytes <= wavid::MAX_FILE_BYTES,
            "test payload exceeds WAVID resource limit"
        );
        let membership = config.weighted_membership()?;
        let weight = membership
            .weight(self.absent.iter().copied())
            .map_err(anyhow::Error::msg)?;
        ensure!(
            weight < membership.threshold,
            "absent weight must be strictly below T"
        );
        ensure!(
            !self.absent.contains(&config.id),
            "this node is declared absent"
        );
        Ok((0..config.num_nodes)
            .filter(|id| !self.absent.contains(id))
            .collect())
    }
}

/// Register signal handlers before starting a service, and await signals asynchronously.
pub struct Shutdown {
    #[cfg(unix)]
    terminate: tokio::signal::unix::Signal,
}
impl Shutdown {
    pub fn new() -> Result<Self> {
        Ok(Self {
            #[cfg(unix)]
            terminate: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?,
        })
    }
    pub async fn wait(&mut self) -> Result<()> {
        #[cfg(unix)]
        tokio::select! {
            result = tokio::signal::ctrl_c() => result?,
            _ = self.terminate.recv() => {},
        }
        #[cfg(not(unix))]
        tokio::signal::ctrl_c().await?;
        Ok(())
    }
}

type Spawn<R, E> = fn(Node, Receiver<R>, Sender<E>, Vec<R>) -> Result<oneshot::Sender<()>>;
async fn serve<R: Send + 'static, E: Send + 'static>(
    config: Node,
    protocol: &str,
    options: &Options,
    spawn: Spawn<R, E>,
    registration: R,
    requests: Vec<R>,
    collect: impl Fn(E) -> Result<Option<Value>>,
) -> Result<()> {
    if let Some(path) = &options.result_file {
        ensure!(
            !path.exists(),
            "result file already exists: {}",
            path.display()
        );
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            tokio::fs::create_dir_all(parent).await?;
        }
    }
    let mut shutdown = Shutdown::new()?;
    let (input, receiver) = channel(1024);
    let (output, mut events) = channel(1024);
    // Manifest installation precedes listener binding. Peers may start in any order.
    let exit = spawn(config.clone(), receiver, output, vec![registration])?;
    println!(
        "{}",
        json!({"event":"ready", "protocol":protocol, "node":config.id, "pid":std::process::id()})
    );
    for request in requests {
        input
            .send(request)
            .await
            .map_err(|_| anyhow!("protocol request channel closed"))?;
    }
    let deadline = tokio::time::sleep(options.timeout);
    tokio::pin!(deadline);
    let mut delivered = false;
    loop {
        tokio::select! {
            stopped = shutdown.wait() => {
                stopped?;
                let _ = exit.send(());
                tokio::task::yield_now().await;
                return Ok(());
            },
            _ = &mut deadline, if !delivered => return Err(anyhow!("{} node {} timed out waiting for a test result", protocol, config.id)),
            event = events.recv() => {
                let event = event.ok_or_else(||anyhow!("{} event stream closed", protocol))?;
                if let Some(result) = collect(event)? {
                    ensure!(!delivered, "duplicate protocol output");
                    let report = json!({"event":"output", "protocol":protocol, "node":config.id,
                        "pid":std::process::id(), "session_id":config.session_id, "result":result});
                    if let Some(path) = &options.result_file {
                        let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
                        tokio::fs::write(&temporary, serde_json::to_vec(&report)?).await?;
                        tokio::fs::rename(&temporary, path).await.context("publish test result")?;
                    }
                    println!("{}", report);
                    delivered = true;
                    // Keep the protocol and its event consumer alive for delayed peers.
                    // The script terminates processes only after every expected output is checked.
                }
            }
        }
    }
}

pub fn test_payload(bytes: usize) -> Vec<u8> {
    (0..bytes)
        .map(|i| ((i % 256 * 31 + 17) % 256) as u8)
        .collect()
}
fn file_result(bytes: Vec<u8>, expected: &[u8]) -> Result<Option<Value>> {
    ensure!(bytes == expected, "incorrect test payload");
    let hash = crypto::hash::do_hash(&bytes)
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
    Ok(Some(json!({"bytes":bytes.len(), "sha256":hash})))
}

pub async fn wra(config: Node, options: Options) -> Result<()> {
    options.active(&config)?;
    let instance = InstanceId::new(0, None, 0);
    serve(
        config,
        "wra",
        &options,
        wra::Context::spawn_with_manifest,
        wra::Request::Register {
            instance,
            header_id: [17; 32],
        },
        vec![wra::Request::Input {
            instance,
            value: true,
        }],
        |event| match event {
            wra::Event::Output { value, .. } => {
                ensure!(value, "unanimous true input produced false");
                Ok(Some(json!(value)))
            }
            wra::Event::Rejected { reason, .. } => Err(anyhow!(reason)),
            _ => Ok(None),
        },
    )
    .await
}
pub async fn wavid(config: Node, options: Options) -> Result<()> {
    let active = options.active(&config)?;
    let dealer = active[0];
    let instance = InstanceId::new(0, Some(dealer), 0);
    let data = test_payload(options.payload_bytes);
    let mut requests = vec![wavid::Request::Retrieve { instance }];
    if config.id == dealer {
        requests.push(wavid::Request::Disperse {
            instance,
            data: data.clone(),
        });
    }
    serve(
        config,
        "wavid",
        &options,
        wavid::Context::spawn_with_manifest,
        wavid::Request::Register {
            instance,
            descriptor: wavid::Descriptor {
                file_bytes: data.len(),
                root: None,
                retrievers: active,
                completion: wavid::CompletionMode::Storage,
            },
        },
        requests,
        |event| match event {
            wavid::Event::Result {
                result: wavid::Retrieval::File(bytes),
                ..
            } => file_result(bytes, &data),
            wavid::Event::Result {
                result: wavid::Retrieval::Invalid(_),
                ..
            } => Err(anyhow!("honest WAVID payload rejected")),
            wavid::Event::Rejected { reason, .. } => Err(anyhow!(reason)),
            _ => Ok(None),
        },
    )
    .await
}
pub async fn wrbc(config: Node, options: Options) -> Result<()> {
    let active = options.active(&config)?;
    let dealer = active[0];
    let instance = InstanceId::new(0, Some(dealer), 0);
    let data = test_payload(options.payload_bytes);
    let requests = if config.id == dealer {
        vec![wrbc::Request::Broadcast {
            instance,
            data: data.clone(),
        }]
    } else {
        vec![]
    };
    serve(
        config,
        "wrbc",
        &options,
        wrbc::Context::spawn_with_manifest,
        wrbc::Request::Register {
            instance,
            file_bytes: data.len(),
        },
        requests,
        |event| match event {
            wrbc::Event::Deliver { data: bytes, .. } => file_result(bytes, &data),
            wrbc::Event::Invalid { .. } => Err(anyhow!("honest WRBC payload rejected")),
            wrbc::Event::Rejected { reason, .. } => Err(anyhow!(reason)),
            _ => Ok(None),
        },
    )
    .await
}
pub async fn wgather(config: Node, options: Options) -> Result<()> {
    let active = options.active(&config)?;
    let instance = InstanceId::new(0, None, 0);
    let mut requests = vec![wgather::Request::Start { instance }];
    // Standalone Gather tests supply synthetic, locally validated completion events.
    requests.extend(
        active
            .into_iter()
            .map(|dealer| wgather::Request::Add { instance, dealer }),
    );
    serve(
        config,
        "wgather",
        &options,
        wgather::Context::spawn_with_manifest,
        wgather::Request::Register { instance },
        requests,
        |event| match event {
            wgather::Event::DeliverSet { dealers, .. } => Ok(Some(json!(dealers))),
            wgather::Event::Rejected { reason, .. } => Err(anyhow!(reason)),
            _ => Ok(None),
        },
    )
    .await
}
pub async fn wbinaa(config: Node, options: Options) -> Result<()> {
    options.active(&config)?;
    let instance = InstanceId::new(0, None, 0);
    let inputs = (0..config.num_nodes)
        .map(|c| {
            if c == 0 {
                false
            } else if c == 1 {
                true
            } else {
                (config.id + c) % 2 == 0
            }
        })
        .collect();
    serve(
        config,
        "wbinaa",
        &options,
        wbinaa::Context::spawn_with_manifest,
        wbinaa::Request::Register {
            instance,
            precision: wbinaa::Precision::bits(options.bits),
        },
        vec![wbinaa::Request::Start { instance, inputs }],
        |event| match event {
            wbinaa::Event::DeliverVector { values, .. } => Ok(Some(json!(values
                .iter()
                .map(|d| json!({"numerator":d.numerator.to_string(),"exponent":d.exponent}))
                .collect::<Vec<_>>()))),
            wbinaa::Event::Rejected { reason, .. } => Err(anyhow!(reason)),
            _ => Ok(None),
        },
    )
    .await
}
