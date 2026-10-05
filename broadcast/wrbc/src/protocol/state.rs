use crate::{Event, ProtMsg};
use anyhow::Result;
use crypto::hash::Hash;
use types::{InstanceId, SendAction, WeightedMembership};
/// WRBC introduces no second quorum or network service: every party retrieves WAVID.
pub struct State {
    pub storage: wavid::State,
    pub delivered: Option<wavid::ValidatedFile>,
    pub rejected: bool,
    pub outgoing: Vec<SendAction<ProtMsg>>,
    pub events: Vec<Event>,
}
impl State {
    pub fn new(
        membership: WeightedMembership,
        id: usize,
        instance: InstanceId,
        public_id: Hash,
        file_bytes: usize,
    ) -> Result<Self> {
        Self::with_params(
            membership,
            id,
            instance,
            public_id,
            file_bytes,
            Default::default(),
        )
    }
    /// Select the same public coding parameters at all parties (see WAVID CodingParams).
    pub fn with_params(
        membership: WeightedMembership,
        id: usize,
        instance: InstanceId,
        public_id: Hash,
        file_bytes: usize,
        coding: wavid::CodingParams,
    ) -> Result<Self> {
        let retrievers = (0..membership.n()).collect();
        let mut storage = wavid::State::new(
            membership,
            id,
            instance,
            public_id,
            wavid::Descriptor {
                coding,
                file_bytes,
                root: None,
                retrievers,
                completion: wavid::CompletionMode::Storage,
            },
        )?;
        storage.retrieve()?;
        Ok(Self {
            storage,
            delivered: None,
            rejected: false,
            outgoing: vec![],
            events: vec![],
        })
    }
    pub fn broadcast(&mut self, data: &[u8]) -> Result<()> {
        self.storage.disperse(data)?;
        self.collect();
        Ok(())
    }
    pub fn receive(&mut self, sender: usize, msg: ProtMsg) {
        self.storage.receive(sender, msg);
        self.collect();
    }
    fn collect(&mut self) {
        self.outgoing
            .extend(std::mem::take(&mut self.storage.outgoing));
        for event in std::mem::take(&mut self.storage.events) {
            if let wavid::Event::Result { instance, result } = event {
                match result {
                    wavid::Retrieval::File(data) => {
                        if self.delivered.is_none() && !self.rejected {
                            self.delivered = Some(data.clone());
                            self.events.push(Event::Deliver { instance, data });
                        }
                    }
                    wavid::Retrieval::Invalid(proof) => {
                        if self.delivered.is_none() && !self.rejected {
                            self.rejected = true;
                            self.events.push(Event::Invalid { instance, proof });
                        }
                    }
                }
            }
        }
    }
}
