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
            match request {
                Request::Register { file_bytes, .. } => {
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
                            file_bytes,
                        )?,
                    );
                }
                Request::Broadcast { data, .. } => self
                    .states
                    .get_mut(&instance)
                    .ok_or_else(|| anyhow::anyhow!("unregistered instance"))?
                    .broadcast(&data)?,
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
