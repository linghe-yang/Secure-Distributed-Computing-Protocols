use serde::{Deserialize, Serialize};
use types::{InstanceId, Replica};
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Kind {
    Inform(Vec<u8>),
    Ack,
    Prepare(Vec<u8>),
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtMsg {
    pub instance: InstanceId,
    pub kind: Kind,
}
#[derive(Clone, Debug)]
pub enum Request {
    Register {
        instance: InstanceId,
    },
    Start {
        instance: InstanceId,
    },
    Add {
        instance: InstanceId,
        dealer: Replica,
    },
}
impl Request {
    pub fn instance(&self) -> InstanceId {
        match self {
            Self::Register { instance } | Self::Start { instance } | Self::Add { instance, .. } => {
                *instance
            }
        }
    }
}
#[derive(Clone, Debug)]
pub enum Event {
    Registered {
        instance: InstanceId,
    },
    DeliverSet {
        instance: InstanceId,
        dealers: Vec<Replica>,
    },
    Rejected {
        instance: InstanceId,
        reason: String,
    },
}
