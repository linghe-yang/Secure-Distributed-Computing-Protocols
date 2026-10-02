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
    pub fn spawn(
        config: Node,
        input: Receiver<Request>,
        output: Sender<Event>,
    ) -> Result<oneshot::Sender<()>> {
        Self::spawn_with_manifest(config, input, output, Vec::new())
    }
    /// Pre-register expected instances before binding the listener; no global startup barrier is needed.
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
            for action in std::mem::take(&mut state.outgoing) {
                self.network.send(action)?;
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
