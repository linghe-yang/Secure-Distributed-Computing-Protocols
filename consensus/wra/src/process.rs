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
        } else if sender < self.membership.n() {
            if let Some(pending) = self.pending.get_mut(&instance) {
                let ready = matches!(&msg.kind, crate::Kind::Ready(_));
                pending.entry((sender, ready)).or_insert(msg);
            }
        }
        self.flush(instance).await
    }
    pub(crate) async fn process_request(&mut self, request: Request) -> Result<()> {
        let instance = request.instance();
        let registering = matches!(&request, Request::Register { .. } | Request::Expect { .. });
        let result = (|| -> Result<()> {
            match request {
                Request::Expect { instance } => {
                    ensure!(instance.valid(self.membership.n()), "invalid instance");
                    ensure!(
                        !self.states.contains_key(&instance)
                            && !self.pending.contains_key(&instance),
                        "instance already expected or registered"
                    );
                    ensure!(
                        self.states.len() + self.pending.len() < MAX_INSTANCES,
                        "instance limit"
                    );
                    self.pending.insert(instance, Default::default());
                }
                Request::Register {
                    instance,
                    header_id,
                } => {
                    ensure!(
                        !self.states.contains_key(&instance),
                        "instance already registered"
                    );
                    ensure!(
                        self.pending.contains_key(&instance)
                            || self.states.len() + self.pending.len() < MAX_INSTANCES,
                        "instance limit"
                    );
                    let mut state =
                        State::new(self.membership.clone(), self.id, instance, header_id)?;
                    if let Some(pending) = self.pending.remove(&instance) {
                        for ((sender, _), msg) in pending {
                            state.receive(sender, msg);
                        }
                    }
                    self.states.insert(instance, state);
                }
                Request::Input { value, .. } => self
                    .states
                    .get_mut(&instance)
                    .ok_or_else(|| anyhow::anyhow!("unregistered instance"))?
                    .input(value)?,
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
