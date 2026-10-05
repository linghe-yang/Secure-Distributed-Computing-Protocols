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
    /// Register 的 `instance` 唯一区分调用；`precision` 为共同目标误差
    /// eta，要求 0 < eta <= 1，且所需轮数不超过 MAX_ROUNDS。通常使用
    /// Precision::bits(b)，表示 eta=2^(-b)；更大 b 意味着更多轮次和通信。
    /// Start.inputs 长度必须等于物理节点数 n；第 j 项必须在所有节点上
    /// 代表同一个上层对象，值为本节点对该对象的布尔输入。每实例启动一次。
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
                    precision,
                } => State::new(membership.clone(), config.id, instance, precision)?,
                _ => {
                    return Err(anyhow::anyhow!(
                        "manifest must contain Register requests only"
                    ))
                }
            };
            states.insert(instance, state);
            startup.push(instance);
        }
        let network = Endpoint::bind(&config, "wbinaa")?;
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
                log::error!("wbinaa service: {}", e);
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
            self.network
                .sender()
                .send_batch(std::mem::take(&mut state.outgoing))?;
            for event in std::mem::take(&mut state.events) {
                if self.output.send(event).await.is_err() {
                    log::debug!("wbinaa output receiver closed; retaining peer service");
                }
            }
        }
        Ok(())
    }
}
