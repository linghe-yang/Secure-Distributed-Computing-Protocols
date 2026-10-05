use crypto::hash::Hash;
use serde::{Deserialize, Serialize};
use types::InstanceId;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Kind {
    Echo(bool),
    Ready(bool),
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtMsg {
    pub instance: InstanceId,
    pub header_id: Hash,
    pub kind: Kind,
}
#[derive(Clone, Debug)]
pub enum Request {
    Expect {
        instance: InstanceId,
    },
    Register {
        instance: InstanceId,
        header_id: Hash,
    },
    Input {
        instance: InstanceId,
        value: bool,
    },
}
impl Request {
    pub fn instance(&self) -> InstanceId {
        match self {
            Self::Expect { instance }
            | Self::Register { instance, .. }
            | Self::Input { instance, .. } => *instance,
        }
    }
}
#[derive(Clone, Debug)]
pub enum Event {
    Registered {
        instance: InstanceId,
    },
    Output {
        instance: InstanceId,
        value: bool,
    },
    Rejected {
        instance: InstanceId,
        reason: String,
    },
}
