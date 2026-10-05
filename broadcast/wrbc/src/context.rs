use crate::{Event, ProtMsg, Request, State};
use anyhow::Result;
use config::Node;
use std::collections::HashMap;
use tokio::sync::{
    mpsc::{Receiver, Sender},
    oneshot,
};
use types::{InstanceId, WeightedMembership};
use util::weighted::Endpoint;

pub struct Context {
    pub(crate) network: Endpoint<ProtMsg>,
    pub(crate) membership: WeightedMembership,
    pub(crate) id: usize,
    pub(crate) states: HashMap<InstanceId, State>,
    input: Receiver<Request>,
    pub(crate) output: Sender<Event>,
    exit_rx: oneshot::Receiver<()>,
    startup: Vec<InstanceId>,
}
impl Context {
    /// 启动当前物理节点的协议服务；必须在 Tokio runtime 内调用。
    ///
    /// # 参数选择
    /// * `config`：`id` 对应本机；`net_map` 和 `sk_map` 配置所有节点的
    ///   地址与认证密钥。`weights` 使用正整数，腐化总权重必须严格小于
    ///   `weight_threshold = T`，且 `3T <= W`。`T` 不是“允许腐化节点数”。
    ///   同一调用共享新的 `session_id`、成员表和阈值。不同服务若同时运行，
    ///   必须使用不同监听地址；同一个服务内由 `InstanceId` 区分实例，
    ///   不为每个实例另开端口，也不自动给端口增加偏移。
    /// * `input`：有界请求通道。先 Register，再提交输入；跨进程启动建议
    ///   使用 `spawn_with_manifest`，防止远端消息早于本地注册。
    /// * `output`：有界事件通道，调用方应持续消费；通道塞满会暂停本服务。
    ///   容量按并发实例的事件突发量选择（单实例测试可取 64）。
    ///
    /// 返回停止句柄：发送 () 或丢弃句柄都会停止服务。应保留到上层确认
    /// 无后续服务义务；本地输出完成并不意味着其他节点已完成。
    /// Register 的 `instance` 必须指定 dealer；每个实例只 Broadcast 一次。
    /// `file_bytes` 为精确文件长度（允许空文件，上限 MAX_FILE_BYTES）。
    /// `coding` 与 WAVID 一致：默认 32 字节；偶数 32..=4096，所有节点一致。
    /// 较大块减少条带但增大证据，详见 wavid::CodingParams。WRBC 自动让所有
    /// 节点恢复，不需要调用方另启 WAVID 网络服务。Deliver 返回可共享的
    /// ValidatedFile，也可用于按需源块证明；as_ref() 读取数据不复制。
    pub fn spawn(
        config: Node,
        input: Receiver<Request>,
        output: Sender<Event>,
    ) -> Result<oneshot::Sender<()>> {
        Self::spawn_with_manifest(config, input, output, Vec::new())
    }
    /// 监听前安装实例清单，适合跨进程启动，避免消息早到导致丢弃。
    ///
    /// `config`、`input`、`output` 的选取与停止句柄语义见 [Self::spawn]。
    /// `registrations` 最多 MAX_INSTANCES 个，不允许重复 InstanceId；
    /// 只接受 Register，其他请求须通过 input 提交。
    /// 每个实例的公开参数须与其他参与节点一致，具体选取见 [Self::spawn]。
    pub fn spawn_with_manifest(
        config: Node,
        input: Receiver<Request>,
        output: Sender<Event>,
        registrations: Vec<Request>,
    ) -> Result<oneshot::Sender<()>> {
        config.validate_weighted()?;
        anyhow::ensure!(
            registrations.len() <= util::weighted::MAX_INSTANCES,
            "instance limit"
        );
        let membership = config.weighted_membership()?;
        let public_id = config.weighted_public_id("wrbc");
        let mut states = HashMap::new();
        let mut startup = vec![];
        for request in registrations {
            let instance = request.instance();
            anyhow::ensure!(
                !states.contains_key(&instance),
                "duplicate manifest instance"
            );
            let state = match request {
                Request::Register {
                    instance,
                    file_bytes,
                    coding,
                } => State::with_params(
                    membership.clone(),
                    config.id,
                    instance,
                    public_id,
                    file_bytes,
                    coding,
                )?,
                _ => {
                    return Err(anyhow::anyhow!(
                        "manifest must contain Register requests only"
                    ))
                }
            };
            states.insert(instance, state);
            startup.push(instance);
        }
        let network = Endpoint::bind(&config, "wrbc")?;
        let (exit_tx, exit_rx) = oneshot::channel();
        let mut context = Self {
            network,
            membership,
            id: config.id,
            states,
            input,
            output,
            exit_rx,
            startup,
        };
        tokio::spawn(async move {
            if let Err(e) = context.run().await {
                log::error!("wrbc service: {}", e);
            }
        });
        Ok(exit_tx)
    }
    pub async fn run(&mut self) -> Result<()> {
        for instance in std::mem::take(&mut self.startup) {
            let _ = self.output.send(Event::Registered { instance }).await;
        }
        let mut input_open = true;
        loop {
            tokio::select! {
                _=&mut self.exit_rx=>break,
                msg=self.network.recv.recv()=>match msg{Some((sender,msg))=>self.process_msg(sender,msg).await?,None=>break},
                request=self.input.recv(), if input_open=>match request{Some(request)=>self.process_request(request).await?,None=>input_open=false},
            }
        }
        Ok(())
    }
    pub(crate) async fn flush(&mut self, instance: InstanceId) -> Result<()> {
        if let Some(state) = self.states.get_mut(&instance) {
            let actions = std::mem::take(&mut state.outgoing);
            if !actions.is_empty() {
                let sender = self.network.sender();
                util::weighted_compute::run(move || sender.send_batch(actions)).await??;
            }
            for event in std::mem::take(&mut state.events) {
                if self.output.send(event).await.is_err() {
                    log::debug!("wrbc output receiver closed; retaining peer service");
                }
            }
        }
        Ok(())
    }
}
