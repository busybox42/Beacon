use std::error::Error;
use futures::StreamExt;
use libp2p::{
    self,
    gossipsub,
    Multiaddr,
    PeerId,
    swarm::SwarmEvent,
};
use tokio::sync::mpsc;
use tracing::{info, error, warn};

use crate::protocol::message::{BeaconMessage, MessageType};
use crate::protocol::types::SystemMessageType;
use super::behaviour::BeaconBehaviour;
use super::behaviour::BeaconEvent;
use super::commands::NetworkCommand;
use super::config::NetworkConfig;
use super::discovery::PeerDiscovery;

pub struct BeaconNetwork {
    swarm: libp2p::Swarm<BeaconBehaviour>,
    message_sender: mpsc::UnboundedSender<NetworkCommand>,
    message_receiver: mpsc::UnboundedReceiver<NetworkCommand>,
    peer_id: PeerId,
}

impl BeaconNetwork {
    pub async fn new() -> Result<Self, Box<dyn Error>> {
        let config = NetworkConfig::new();
        info!("Local peer id: {}", config.peer_id);

        // Build the swarm
        let swarm = libp2p::SwarmBuilder::with_existing_identity(config.key_pair)
            .with_tokio()
            .with_tcp(
                libp2p::tcp::Config::default(),
                libp2p::tls::Config::new,
                libp2p::yamux::Config::default,
            )?
            .with_behaviour(|key| {
                Ok(BeaconBehaviour {
                    ping: libp2p::ping::Behaviour::new(libp2p::ping::Config::new()),
                    identify: libp2p::identify::Behaviour::new(libp2p::identify::Config::new(
                        "beacon/1.0.0".into(),
                        key.public(),
                    )),
                    mdns: libp2p::mdns::tokio::Behaviour::new(libp2p::mdns::Config::default(), config.peer_id)?,
                    gossipsub: gossipsub::Behaviour::new(
                        gossipsub::MessageAuthenticity::Signed(key.clone()),
                        NetworkConfig::gossipsub_config(),
                    )?,
                })
            })?
            .build();

        // Create message channels
        let (sender, receiver) = mpsc::unbounded_channel();

        Ok(BeaconNetwork {
            swarm,
            message_sender: sender,
            message_receiver: receiver,
            peer_id: config.peer_id,
        })
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn Error>> {
        // Listen on all interfaces
        let addr: Multiaddr = "/ip4/0.0.0.0/tcp/0".parse()?;
        self.swarm.listen_on(addr)?;

        // Subscribe to topics
        let (broadcast_topic, private_topic) = NetworkConfig::topics();
        self.swarm.behaviour_mut().gossipsub.subscribe(&broadcast_topic)?;
        self.swarm.behaviour_mut().gossipsub.subscribe(&private_topic)?;

        loop {
            tokio::select! {
                event = self.swarm.select_next_some() => {
                    match event {
                        SwarmEvent::Behaviour(BeaconEvent::Gossipsub(
                            gossipsub::Event::Message {
                                propagation_source: _,
                                message_id: _,
                                message,
                            }
                        )) => {
                            if let Ok(beacon_message) = serde_json::from_slice::<BeaconMessage>(&message.data) {
                                match beacon_message.message_type {
                                    MessageType::Broadcast(content) => {
                                        info!(
                                            "Broadcast from {}: {}",
                                            beacon_message.sender,
                                            content
                                        );
                                    }
                                    MessageType::Private(content) => {
                                        if let Some(recipient) = beacon_message.recipient {
                                            if recipient == self.peer_id.to_string() {
                                                info!(
                                                    "Private message from {}: {}",
                                                    beacon_message.sender,
                                                    content
                                                );
                                            }
                                        }
                                    }
                                    MessageType::Encrypted(_encrypted_msg) => {
                                        warn!(
                                            "Received encrypted message from {}. Decryption not implemented.",
                                            beacon_message.sender
                                        );
                                    }
                                    MessageType::System(system_type, content) => {
                                        match system_type {
                                            SystemMessageType::UserJoined => {
                                                info!(
                                                    "User {} joined the network. Message: {}",
                                                    beacon_message.sender,
                                                    content
                                                );
                                            }
                                            SystemMessageType::UserLeft => {
                                                info!(
                                                    "User {} left the network. Message: {}",
                                                    beacon_message.sender,
                                                    content
                                                );
                                            }
                                            _ => {
                                                info!(
                                                    "Received system message of type {:?} from {}. Content: {}",
                                                    system_type,
                                                    beacon_message.sender,
                                                    content
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        SwarmEvent::Behaviour(BeaconEvent::Mdns(libp2p::mdns::Event::Discovered(peers))) => {
                            for (peer_id, _addr) in peers {
                                PeerDiscovery::handle_peer_discovered(&mut self.swarm, peer_id);
                            }
                        }
                        SwarmEvent::NewListenAddr { address, .. } => {
                            info!("Listening on {address}");
                        }
                        _ => {}
                    }
                }
                Some(command) = self.message_receiver.recv() => {
                    match command {
                        NetworkCommand::Broadcast(content) => {
                            let message = BeaconMessage::new_broadcast(content, self.peer_id);
                            let encoded = serde_json::to_vec(&message)?;
                            let topic = gossipsub::IdentTopic::new("beacon-broadcasts");
                            if let Err(e) = self.swarm.behaviour_mut().gossipsub.publish(topic, encoded) {
                                error!("Broadcasting error: {e}");
                            }
                        }
                        NetworkCommand::Private(content, recipient) => {
                            let message = BeaconMessage::new_private(content, self.peer_id, recipient);
                            let encoded = serde_json::to_vec(&message)?;
                            let topic = gossipsub::IdentTopic::new("beacon-messages");
                            if let Err(e) = self.swarm.behaviour_mut().gossipsub.publish(topic, encoded) {
                                error!("Private message error: {e}");
                            }
                        }
                        NetworkCommand::EncryptedPrivate { 
                            encrypted_message, 
                            recipient, 
                            sender_public_key 
                        } => {
                            let message = BeaconMessage::new_encrypted(
                                encrypted_message, 
                                self.peer_id, 
                                Some(recipient), 
                                sender_public_key
                            );
                            let encoded = serde_json::to_vec(&message)?;
                            let topic = gossipsub::IdentTopic::new("beacon-encrypted-messages");
                            if let Err(e) = self.swarm.behaviour_mut().gossipsub.publish(topic, encoded) {
                                error!("Encrypted message error: {e}");
                            }
                        }
                        NetworkCommand::System { message_type, content } => {
                            let message = BeaconMessage::new_system(message_type, content, self.peer_id);
                            let encoded = serde_json::to_vec(&message)?;
                            let topic = gossipsub::IdentTopic::new("beacon-system-messages");
                            if let Err(e) = self.swarm.behaviour_mut().gossipsub.publish(topic, encoded) {
                                error!("System message error: {e}");
                            }
                        }
                        NetworkCommand::EstablishSecureConnection(peer) => {
                            warn!("Secure connection establishment not implemented for peer: {}", peer);
                        }
                        NetworkCommand::UpdateStatus(status) => {
                            info!("Updating user status to: {}", status);
                            // You might want to broadcast a system message about status change
                            let system_message = BeaconMessage::new_system(
                                SystemMessageType::UserJoined, 
                                format!("Status updated to: {}", status), 
                                self.peer_id
                            );
                            let encoded = serde_json::to_vec(&system_message)?;
                            let topic = gossipsub::IdentTopic::new("beacon-system-messages");
                            if let Err(e) = self.swarm.behaviour_mut().gossipsub.publish(topic, encoded) {
                                error!("Status update error: {e}");
                            }
                        }
                    }
                }
            }
        }
    }

    pub fn sender(&self) -> mpsc::UnboundedSender<NetworkCommand> {
        self.message_sender.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_network_creation() {
        let network = BeaconNetwork::new().await;
        assert!(network.is_ok());
    }

    #[tokio::test]
    async fn test_peer_discovery() {
        let mut network = BeaconNetwork::new().await.unwrap();
        let sender = network.sender();
        
        // Start the network in a background task
        let handle = tokio::spawn(async move {
            network.run().await.unwrap();
        });

        // Give some time for network setup
        tokio::time::sleep(Duration::from_secs(1)).await;

        // Try sending a broadcast message
        sender.send(NetworkCommand::Broadcast("Test broadcast".to_string())).unwrap();

        // Wait a bit more for potential peer discovery
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Clean up
        handle.abort();
    }
}