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
    /// WAVID 的实例参数位于 `Request::Register.descriptor`：
    /// * `file_bytes`：规范化 bulk 的精确长度，含上层编码内容、不含 WAVID
    ///   的条带补零；范围 0..=MAX_FILE_BYTES，所有节点必须一致。
    /// * `coding.block_bytes`：单个源块/编码坐标的字节数，偶数 32..=4096；
    ///   默认 32，常见可选 64/128/256。按上层短字段和证明大小选择：增大
    ///   可减少条带及目录，但编码错误证据要携带 n 个块。依赖论文复杂度时
    ///   保持 b=Theta(lambda+log n)，不要随整个 bulk 大小增长。此参数被根绑定，
    ///   注册后不得更换；与固定 32KiB 的网络分包大小无关。
    /// * `root`：已由上层认证的目录根；尚未取得时可为 None，External 模式
    ///   随后用 Pin 绑定。根依赖本服务的 public_id，不可混用 WRBC 的根。
    /// * `retrievers`：允许恢复的物理节点 ID；空列表表示暂不授权，后续
    ///   Authorize 只能追加。授权某节点前，上层须验证其恢复资格。
    /// * `completion`：独立存储测试用 Storage；coin 需要联合私有输入回执时
    ///   用 External，仅在联合完成条件已认证后提交 Complete。Stored 只证明
    ///   本地存储包通过检查，不证明上层私有输入或电路语义。
    /// * `instance`：dealer 为真实发送者 ID；epoch/slot 用于区分上层调用，
    ///   同一会话内不得把已用 InstanceId 重新用于另一份 bulk。
    /// 恢复输出的 ValidatedFile 支持 open_source/open_range；保留该共享句柄
    /// 可在无需网络的情况下生成上层证据，数据访问使用 as_ref() 避免复制。
    /// Retrieve 按收到的条带增量恢复；全部条带及补零验证通过后才输出 File。
    /// 单条带已构成公开错误证据时可以提前输出 Invalid；Stored 仍须完整验包。
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
        let public_id = config.weighted_public_id("wavid");
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
                    descriptor,
                } => State::new(
                    membership.clone(),
                    config.id,
                    instance,
                    public_id,
                    descriptor,
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
        let network = Endpoint::bind(&config, "wavid")?;
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
                log::error!("wavid service: {}", e);
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
                    log::debug!("wavid output receiver closed; retaining peer service");
                }
            }
        }
        Ok(())
    }
}
