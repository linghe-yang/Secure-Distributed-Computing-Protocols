use crate::{Context, Event, ProtMsg, Request, State};
use anyhow::{ensure, Result};
use util::weighted::MAX_INSTANCES;
impl Context {
    pub(crate) async fn process_msg(&mut self, sender: usize, msg: ProtMsg) -> Result<()> {
        log::debug!(
            "Node {}: received message from node {} for instance {:?}",
            self.id,
            sender,
            msg.instance
        );
        let instance = msg.instance;
        if let Some(state) = self.states.get_mut(&instance) {
            state.receive(sender, msg);
        }
        self.flush(instance).await
    }
    pub(crate) async fn process_request(&mut self, request: Request) -> Result<()> {
        let instance = request.instance();
        let registering = matches!(&request, Request::Register { .. });
        let result = (|| -> Result<()> {
            if let Request::Register { descriptor, .. } = request {
                ensure!(
                    !self.states.contains_key(&instance) && self.states.len() < MAX_INSTANCES,
                    "duplicate registration or instance limit"
                );
                self.states.insert(
                    instance,
                    State::new(
                        self.membership.clone(),
                        self.id,
                        instance,
                        self.network.public_id,
                        descriptor,
                    )?,
                );
            } else {
                let state = self
                    .states
                    .get_mut(&instance)
                    .ok_or_else(|| anyhow::anyhow!("unregistered instance"))?;
                match request {
                    Request::Disperse { data, .. } => state.disperse(&data)?,
                    Request::Retrieve { .. } => state.retrieve()?,
                    Request::Authorize { retrievers, .. } => state.authorize(retrievers)?,
                    Request::Complete { root, .. } => state.accept_completion(root)?,
                    Request::Pin { root, .. } => state.pin_root(root)?,
                    Request::Register { .. } => unreachable!(),
                }
            }
            Ok(())
        })();
        if result.is_ok() && registering {
            let _ = self.output.send(Event::Registered { instance }).await;
        }
        if let Err(e) = result {
            let _ = self
                .output
                .send(Event::Rejected {
                    instance,
                    reason: e.to_string(),
                })
                .await;
        }
        self.flush(instance).await
    }
}
