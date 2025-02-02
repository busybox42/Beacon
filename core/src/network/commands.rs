use libp2p::PeerId;
use crate::crypto::{CryptoIdentity, EncryptedMessage};
use crate::protocol::types::SystemMessageType;

/// Enhanced network commands with support for encryption and system messages
#[derive(Debug)]
pub enum NetworkCommand {
    /// Broadcast an unencrypted message to all peers
    Broadcast(String),
    
    /// Send an unencrypted private message to a specific peer
    Private(String, PeerId),
    
    /// Send an encrypted private message
    EncryptedPrivate {
        /// The encrypted message payload
        encrypted_message: EncryptedMessage,
        /// Recipient's peer ID
        recipient: PeerId,
        /// Sender's public key for verification
        sender_public_key: Vec<u8>,
    },
    
    /// Send a system or control message
    System {
        /// Type of system message
        message_type: SystemMessageType,
        /// Message content
        content: String,
    },
    
    /// Request to establish a secure connection with a peer
    EstablishSecureConnection(PeerId),
    
    /// Update user's online status
    UpdateStatus(String),
}

impl NetworkCommand {
    /// Create a broadcast command
    pub fn broadcast(message: String) -> Self {
        NetworkCommand::Broadcast(message)
    }
    
    /// Create a private message command
    pub fn private(message: String, recipient: PeerId) -> Self {
        NetworkCommand::Private(message, recipient)
    }
    
    /// Create an encrypted private message command
    pub fn encrypted_private(
        crypto_identity: &CryptoIdentity, 
        message: &[u8], 
        recipient_public_key: &x25519_dalek::PublicKey,
        recipient: PeerId
    ) -> Result<Self, crate::crypto::CryptoError> {
        let encrypted_message = crypto_identity.encrypt_message(*recipient_public_key, message)?;
        
        Ok(NetworkCommand::EncryptedPrivate {
            encrypted_message,
            recipient,
            sender_public_key: crypto_identity.ed25519_public_key().as_bytes().to_vec(),
        })
    }
    
    /// Create a system message command
    pub fn system(message_type: SystemMessageType, content: String) -> Self {
        NetworkCommand::System { 
            message_type, 
            content 
        }
    }
    
    /// Request to establish a secure connection
    pub fn establish_secure_connection(peer: PeerId) -> Self {
        NetworkCommand::EstablishSecureConnection(peer)
    }
    
    /// Update user status
    pub fn update_status(status: String) -> Self {
        NetworkCommand::UpdateStatus(status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::types::SystemMessageType;
    use rand::rngs::OsRng;

    #[test]
    fn test_network_command_creation() {
        // Test broadcast command
        let broadcast = NetworkCommand::broadcast("Hello, world!".to_string());
        assert!(matches!(broadcast, NetworkCommand::Broadcast(_)));

        // Test private message command
        let recipient = PeerId::random();
        let private = NetworkCommand::private("Secret message".to_string(), recipient.clone());
        assert!(matches!(private, NetworkCommand::Private(_, _)));

        // Test system message command
        let system = NetworkCommand::system(
            SystemMessageType::UserJoined, 
            "New user connected".to_string()
        );
        assert!(matches!(system, NetworkCommand::System { .. }));

        // Test encrypted private message
        let sender = CryptoIdentity::new().unwrap();
        let recipient = CryptoIdentity::new().unwrap();
    
        let encrypted_cmd = NetworkCommand::encrypted_private(
            &sender, 
            b"Encrypted communication", 
            &recipient.x25519_public_key(),
            recipient.x25519_public_key().to_string().parse().unwrap()
        );
    
        assert!(encrypted_cmd.is_ok());
    }
}