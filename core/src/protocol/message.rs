use serde::{Deserialize, Serialize};
use libp2p::PeerId;
use crate::crypto::EncryptedMessage;
use crate::protocol::types::SystemMessageType;

/// Represents different types of messages in the Beacon protocol
#[derive(Debug, Serialize, Deserialize)]
pub enum MessageType {
    /// Unencrypted broadcast message
    Broadcast(String),
    /// Unencrypted private message
    Private(String),
    /// Encrypted message
    Encrypted(EncryptedMessageWrapper),
    /// System or control message
    System(SystemMessageType, String),
}

/// Wrapper for encrypted messages to include additional metadata
#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedMessageWrapper {
    /// The encrypted payload
    pub ciphertext: Vec<u8>,
    /// Nonce used for encryption
    pub nonce: Vec<u8>,
    /// Optional signature for message authenticity
    pub signature: Option<Vec<u8>>,
    /// Sender's public key used for verification
    pub sender_public_key: Vec<u8>,
}

/// Primary message structure for Beacon protocol
#[derive(Debug, Serialize, Deserialize)]
pub struct BeaconMessage {
    /// Type of message
    pub message_type: MessageType,
    /// Sender's peer ID
    pub sender: String,
    /// Optional recipient's peer ID
    pub recipient: Option<String>,
    /// Timestamp of the message
    pub timestamp: u64,
}

impl BeaconMessage {
    /// Create a new broadcast message
    pub fn new_broadcast(content: String, sender: PeerId) -> Self {
        Self {
            message_type: MessageType::Broadcast(content),
            sender: sender.to_string(),
            recipient: None,
            timestamp: current_timestamp(),
        }
    }

    /// Create a new private message
    pub fn new_private(content: String, sender: PeerId, recipient: PeerId) -> Self {
        Self {
            message_type: MessageType::Private(content),
            sender: sender.to_string(),
            recipient: Some(recipient.to_string()),
            timestamp: current_timestamp(),
        }
    }

    /// Create a new encrypted message
    pub fn new_encrypted(
        encrypted_msg: EncryptedMessage, 
        sender: PeerId, 
        recipient: Option<PeerId>,
        sender_public_key: Vec<u8>
    ) -> Self {
        Self {
            message_type: MessageType::Encrypted(EncryptedMessageWrapper {
                ciphertext: encrypted_msg.ciphertext.clone(),
                nonce: encrypted_msg.nonce.clone(),
                signature: encrypted_msg.signature.clone(),
                sender_public_key,
            }),
            sender: sender.to_string(),
            recipient: recipient.map(|r| r.to_string()),
            timestamp: current_timestamp(),
        }
    }

    /// Create a new system message
    pub fn new_system(
        system_type: SystemMessageType, 
        content: String, 
        sender: PeerId
    ) -> Self {
        Self {
            message_type: MessageType::System(system_type, content),
            sender: sender.to_string(),
            recipient: None,
            timestamp: current_timestamp(),
        }
    }
}

/// Get the current timestamp
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::CryptoIdentity;

    #[test]
    fn test_message_creation() {
        // Create sender and recipient peer IDs
        let sender_id = PeerId::random();
        let recipient_id = PeerId::random();

        // Broadcast message
        let broadcast = BeaconMessage::new_broadcast(
            "Hello, world!".to_string(), 
            sender_id.clone()
        );
        assert!(matches!(broadcast.message_type, MessageType::Broadcast(_)));
        assert_eq!(broadcast.sender, sender_id.to_string());

        // Private message
        let private = BeaconMessage::new_private(
            "Secret message".to_string(), 
            sender_id.clone(), 
            recipient_id.clone()
        );
        assert!(matches!(private.message_type, MessageType::Private(_)));
        assert_eq!(private.recipient, Some(recipient_id.to_string()));

        // Encrypted message
        let alice = CryptoIdentity::new().unwrap();
        let bob = CryptoIdentity::new().unwrap();
        
        let original_message = b"Encrypted communication";
        let encrypted_msg = alice.encrypt_message(bob.x25519_public_key(), original_message).unwrap();
        
        let encrypted = BeaconMessage::new_encrypted(
            encrypted_msg, 
            sender_id.clone(), 
            Some(recipient_id.clone()), 
            alice.ed25519_public_key().to_bytes().to_vec()
        );
        
        assert!(matches!(encrypted.message_type, MessageType::Encrypted(_)));
    }
}