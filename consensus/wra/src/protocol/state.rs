use crate::{Event, Kind, ProtMsg};
use anyhow::{ensure, Result};
use crypto::hash::Hash;
use num_bigint::BigUint;
use std::collections::HashMap;
use types::{InstanceId, Replica, SendAction, WeightedMembership};
/// One binary RA instance. Output never stops relays or a delayed local input.
pub struct State {
    pub membership: WeightedMembership,
    pub id: Replica,
    pub instance: InstanceId,
    pub header_id: Hash,
    pub input_value: Option<bool>,
    pub ready_value: Option<bool>,
    pub output: Option<bool>,
    pub(crate) echoes: HashMap<Replica, bool>,
    pub(crate) readies: HashMap<Replica, bool>,
    pub echo_weights: [BigUint; 2],
    pub ready_weights: [BigUint; 2],
    pub outgoing: Vec<SendAction<ProtMsg>>,
    pub events: Vec<Event>,
}
impl State {
    pub fn new(
        membership: WeightedMembership,
        id: Replica,
        instance: InstanceId,
        header_id: Hash,
    ) -> Result<Self> {
        ensure!(
            id < membership.n() && instance.valid(membership.n()),
            "invalid RA instance/party"
        );
        Ok(Self {
            membership,
            id,
            instance,
            header_id,
            input_value: None,
            ready_value: None,
            output: None,
            echoes: HashMap::new(),
            readies: HashMap::new(),
            echo_weights: Default::default(),
            ready_weights: Default::default(),
            outgoing: vec![],
            events: vec![],
        })
    }
    pub(crate) fn broadcast(&mut self, kind: Kind) {
        for recipient in 0..self.membership.n() {
            self.outgoing.push(SendAction {
                recipient,
                message: ProtMsg {
                    instance: self.instance,
                    header_id: self.header_id,
                    kind: kind.clone(),
                },
            });
        }
    }
    pub fn receive(&mut self, sender: Replica, msg: ProtMsg) {
        if sender >= self.membership.n()
            || msg.instance != self.instance
            || msg.header_id != self.header_id
        {
            return;
        }
        let (slots, weights, value) = match msg.kind {
            Kind::Echo(v) => (&mut self.echoes, &mut self.echo_weights, v),
            Kind::Ready(v) => (&mut self.readies, &mut self.ready_weights, v),
        };
        if let std::collections::hash_map::Entry::Vacant(e) = slots.entry(sender) {
            e.insert(value);
            weights[value as usize] += &self.membership.weights[sender].0;
        }
        self.advance();
    }
}
