use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageType {
    Broadcast(String),
    Private(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconMessage {
    pub message_type: MessageType,
    pub sender: String,  // PeerId as string
    pub recipient: Option<String>,  // Optional recipient PeerId for private messages
    pub timestamp: SystemTime,
}

impl BeaconMessage {
    pub fn new_broadcast(content: String, sender: PeerId) -> Self {
        BeaconMessage {
            message_type: MessageType::Broadcast(content),
            sender: sender.to_string(),
            recipient: None,
            timestamp: SystemTime::now(),
        }
    }

    pub fn new_private(content: String, sender: PeerId, recipient: PeerId) -> Self {
        BeaconMessage {
            message_type: MessageType::Private(content),
            sender: sender.to_string(),
            recipient: Some(recipient.to_string()),
            timestamp: SystemTime::now(),
        }
    }
}