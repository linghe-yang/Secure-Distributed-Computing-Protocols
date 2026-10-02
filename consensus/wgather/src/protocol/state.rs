use crate::{Event, Kind, ProtMsg};
use anyhow::{ensure, Result};
use num_bigint::BigUint;
use types::{InstanceId, SendAction, WeightedMembership};
pub struct State {
    pub membership: WeightedMembership,
    pub id: usize,
    pub instance: InstanceId,
    pub output: Option<Vec<usize>>,
    pub outgoing: Vec<SendAction<ProtMsg>>,
    pub events: Vec<Event>,
    pub(crate) started: bool,
    pub(crate) validated: Vec<u8>,
    pub validated_weight: BigUint,
    pub(crate) informs: Vec<Option<Vec<u8>>>,
    pub(crate) prepares: Vec<Option<Vec<u8>>>,
    pub(crate) ack_sent: Vec<bool>,
    pub(crate) ack_senders: Vec<bool>,
    pub(crate) prepare_senders: Vec<bool>,
    pub ack_weight: BigUint,
    pub prepare_weight: BigUint,
    pub(crate) announced: bool,
    pub(crate) prepared: bool,
}
impl State {
    pub fn new(membership: WeightedMembership, id: usize, instance: InstanceId) -> Result<Self> {
        let n = membership.n();
        ensure!(
            n <= 4096 && id < n && instance.dealer.is_none(),
            "Gather requires a global instance and at most 4096 participants"
        );
        Ok(Self {
            membership,
            id,
            instance,
            output: None,
            outgoing: vec![],
            events: vec![],
            started: false,
            validated: vec![0; n.div_ceil(8)],
            validated_weight: 0u8.into(),
            informs: vec![None; n],
            prepares: vec![None; n],
            ack_sent: vec![false; n],
            ack_senders: vec![false; n],
            prepare_senders: vec![false; n],
            ack_weight: 0u8.into(),
            prepare_weight: 0u8.into(),
            announced: false,
            prepared: false,
        })
    }
    fn valid_bitmap(&self, b: &[u8]) -> bool {
        b.len() == self.validated.len()
            && (self.membership.n() % 8 == 0
                || b.last()
                    .is_some_and(|v| v >> (self.membership.n() % 8) == 0))
    }
    pub(crate) fn subset(&self, b: &[u8]) -> bool {
        b.iter().zip(&self.validated).all(|(b, v)| b & !v == 0)
    }
    pub(crate) fn send(&mut self, recipient: usize, kind: Kind) {
        self.outgoing.push(SendAction {
            recipient,
            message: ProtMsg {
                instance: self.instance,
                kind,
            },
        });
    }
    pub(crate) fn broadcast(&mut self, kind: Kind) {
        for peer in 0..self.membership.n() {
            self.send(peer, kind.clone());
        }
    }
    pub fn receive(&mut self, sender: usize, msg: ProtMsg) {
        if sender >= self.membership.n() || msg.instance != self.instance {
            return;
        }
        match msg.kind {
            Kind::Ack => {
                if !self.ack_senders[sender] {
                    self.ack_senders[sender] = true;
                    self.ack_weight += &self.membership.weights[sender].0;
                }
            }
            Kind::Inform(b) => {
                if self.valid_bitmap(&b) && self.informs[sender].is_none() {
                    self.informs[sender] = Some(b);
                }
            }
            Kind::Prepare(b) => {
                if self.valid_bitmap(&b) && self.prepares[sender].is_none() {
                    self.prepares[sender] = Some(b);
                }
            }
        }
        self.advance();
    }
    pub fn start(&mut self) -> Result<()> {
        ensure!(!self.started, "Gather already started");
        self.started = true;
        self.advance();
        Ok(())
    }
    /// Only an application-verified completion event may call add; peer assertions do not validate dealers.
    pub fn add(&mut self, dealer: usize) -> Result<()> {
        ensure!(dealer < self.membership.n(), "unknown dealer");
        let bit = 1 << (dealer % 8);
        if self.validated[dealer / 8] & bit == 0 {
            self.validated[dealer / 8] |= bit;
            self.validated_weight += &self.membership.weights[dealer].0;
            self.advance();
        }
        Ok(())
    }
}
