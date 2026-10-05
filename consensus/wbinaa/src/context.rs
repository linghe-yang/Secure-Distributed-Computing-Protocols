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
    /// Start this physical node's protocol service inside a Tokio runtime.
    ///
    /// # Parameter selection
    /// * `config`: set `id` to the local node ID and populate `net_map` and
    ///   `sk_map` with every participant's address and authentication key.
    ///   Use positive integer `weights`; actual corrupt weight must be strictly
    ///   below `weight_threshold = T`, with `3T <= W`. T bounds weight, not the
    ///   number of corrupt nodes. Participants share a fresh `session_id`,
    ///   membership, and threshold for each invocation. Concurrent services need
    ///   distinct listening addresses. One service multiplexes `InstanceId` values
    ///   on its listener; it does not allocate ports or apply offsets per instance.
    /// * `input`: a bounded request channel. Register before submitting input.
    ///   Prefer `spawn_with_manifest` across processes so peer messages cannot
    ///   arrive before local registration.
    /// * `output`: a bounded event channel that the caller must continuously drain.
    ///   A full channel pauses this service. Size it for event bursts across
    ///   concurrent instances; 64 is sufficient for a single-instance test.
    ///
    /// Sending () on the returned handle, or dropping it, stops the service.
    /// Retain it until the application confirms that no peer-service obligations
    /// remain; local output does not imply that other participants have finished.
    /// Register's `instance` uniquely identifies a call. `precision` is the
    /// common target error eta, with 0 < eta <= 1 and at most MAX_ROUNDS required.
    /// Typically use Precision::bits(b) for eta=2^(-b); increasing b requires
    /// more rounds and communication. Start.inputs must contain exactly n bits,
    /// where n is the physical participant count. Coordinate j must represent the
    /// same application object at every node and hold that node's Boolean input
    /// for the object. Start each instance once.
    pub fn spawn(
        config: Node,
        input: Receiver<Request>,
        output: Sender<Event>,
    ) -> Result<oneshot::Sender<()>> {
        Self::spawn_with_manifest(config, input, output, Vec::new())
    }
    /// Install the instance manifest before listening, preventing early peer
    /// messages from being discarded during cross-process startup.
    ///
    /// See [Self::spawn] for `config`, `input`, `output`, and shutdown semantics.
    /// `registrations` may contain at most MAX_INSTANCES entries, with no duplicate
    /// InstanceId values. Only Register is accepted; submit other requests
    /// through input. Each instance's public parameters must agree across its
    /// participants; see [Self::spawn] for selection guidance.
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
