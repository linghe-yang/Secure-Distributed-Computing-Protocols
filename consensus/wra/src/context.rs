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
    pub(crate) pending: HashMap<InstanceId, HashMap<(usize, bool), ProtMsg>>,
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
        let mut states = HashMap::new();
        let mut pending = HashMap::new();
        let mut startup = vec![];
        for request in registrations {
            let instance = request.instance();
            anyhow::ensure!(
                !states.contains_key(&instance) && !pending.contains_key(&instance),
                "duplicate manifest instance"
            );
            if let Request::Expect { instance } = request {
                anyhow::ensure!(instance.valid(membership.n()), "invalid instance");
                pending.insert(instance, HashMap::new());
                startup.push(instance);
                continue;
            }
            let state = match request {
                Request::Register {
                    instance,
                    header_id,
                } => State::new(membership.clone(), config.id, instance, header_id)?,
                _ => {
                    return Err(anyhow::anyhow!(
                        "manifest must contain Register or Expect requests only"
                    ))
                }
            };
            states.insert(instance, state);
            startup.push(instance);
        }
        let network = Endpoint::bind(&config, "wra")?;
        let (exit_tx, exit_rx) = oneshot::channel();
        let mut context = Self {
            network,
            membership,
            id: config.id,
            states,
            pending,
            input,
            output,
            exit_rx,
            startup,
        };
        tokio::spawn(async move {
            if let Err(e) = context.run().await {
                log::error!("wra service: {}", e);
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
                    log::debug!("wra output receiver closed; retaining peer service");
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Kind;
    use types::Weight;
    #[tokio::test]
    async fn early_votes_are_bounded_and_replayed_after_header_binding() {
        let mut config = Node::new();
        config.num_nodes = 1;
        config.weights = vec![Weight::from(3)];
        config.weight_threshold = Some(Weight::from(1));
        config.session_id = [7; 32];
        config.net_map.insert(0, "127.0.0.1:0".into());
        config.sk_map.insert(0, vec![7; crypto::SECRET_KEY_SIZE]);
        let network = Endpoint::bind(&config, "wra").unwrap();
        let (_, input) = tokio::sync::mpsc::channel(8);
        let (output, mut events) = tokio::sync::mpsc::channel(8);
        let (_, exit_rx) = oneshot::channel();
        let mut context = Context {
            network,
            membership: config.weighted_membership().unwrap(),
            id: 0,
            states: HashMap::new(),
            pending: HashMap::new(),
            input,
            output,
            exit_rx,
            startup: vec![],
        };
        let instance = InstanceId::new(0, None, 0);
        context
            .process_request(Request::Expect { instance })
            .await
            .unwrap();
        for kind in [Kind::Echo(true), Kind::Ready(true)] {
            for _ in 0..100 {
                context
                    .process_msg(
                        0,
                        ProtMsg {
                            instance,
                            header_id: [8; 32],
                            kind: kind.clone(),
                        },
                    )
                    .await
                    .unwrap();
            }
        }
        assert_eq!(context.pending[&instance].len(), 2);
        assert!(!context.states.contains_key(&instance));
        context
            .process_request(Request::Register {
                instance,
                header_id: [8; 32],
            })
            .await
            .unwrap();
        assert!(context.pending.is_empty());
        assert_eq!(context.states[&instance].output, Some(true));
        assert!(matches!(
            events.recv().await,
            Some(Event::Registered { .. })
        ));
        assert!(matches!(
            events.recv().await,
            Some(Event::Registered { .. })
        ));
        assert!(matches!(
            events.recv().await,
            Some(Event::Output { value: true, .. })
        ));
    }
}
