use libp2p::{gossipsub, identity, PeerId};
use std::hash::{Hash, Hasher, DefaultHasher};
use std::time::Duration;

pub struct NetworkConfig {
    pub peer_id: PeerId,
    pub key_pair: identity::Keypair,
}

impl NetworkConfig {
    pub fn new() -> Self {
        let key_pair = identity::Keypair::generate_ed25519();
        let peer_id = PeerId::from(key_pair.public());
        
        NetworkConfig {
            peer_id,
            key_pair,
        }
    }

    pub fn gossipsub_config() -> gossipsub::Config {
        gossipsub::ConfigBuilder::default()
            .heartbeat_interval(Duration::from_secs(1))
            .validation_mode(gossipsub::ValidationMode::Strict)
            .message_id_fn(|message: &gossipsub::Message| {
                let mut s = DefaultHasher::new();
                message.data.as_slice().hash(&mut s);
                gossipsub::MessageId::from(s.finish().to_string())
            })
            .build()
            .expect("Valid config")
    }

    pub fn topics() -> (gossipsub::IdentTopic, gossipsub::IdentTopic) {
        (
            gossipsub::IdentTopic::new("beacon-broadcasts"),
            gossipsub::IdentTopic::new("beacon-messages")
        )
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self::new()
    }
}