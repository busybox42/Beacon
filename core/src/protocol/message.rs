use serde::{Deserialize, Serialize};
use libp2p::PeerId;

#[derive(Debug, Serialize, Deserialize)]
pub enum MessageType {
    Broadcast(String),
    Private(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BeaconMessage {
    pub message_type: MessageType,
    pub sender: String,
    pub recipient: Option<String>,
}

impl BeaconMessage {
    pub fn new_broadcast(content: String, sender: PeerId) -> Self {
        BeaconMessage {
            message_type: MessageType::Broadcast(content),
            sender: sender.to_string(),
            recipient: None,
        }
    }

    pub fn new_private(content: String, sender: PeerId, recipient: PeerId) -> Self {
        BeaconMessage {
            message_type: MessageType::Private(content),
            sender: sender.to_string(),
            recipient: Some(recipient.to_string()),
        }
    }
}