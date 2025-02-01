use std::error::Error;
use std::hash::{Hash, Hasher, DefaultHasher};
use futures::StreamExt;
use libp2p::{
    self,
    gossipsub,
    identify,
    identity,
    mdns,
    ping,
    swarm::NetworkBehaviour,
    PeerId,
    Multiaddr,
};
use tokio::sync::mpsc;
use tracing::{info, error};

use crate::protocol::message::{BeaconMessage, MessageType};

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "BeaconEvent")]
pub struct BeaconBehaviour {
    ping: ping::Behaviour,
    identify: identify::Behaviour,
    gossipsub: gossipsub::Behaviour,
    mdns: mdns::tokio::Behaviour,
}

#[derive(Debug)]
pub enum BeaconEvent {
    Ping(ping::Event),
    Identify(identify::Event),
    Gossipsub(gossipsub::Event),
    Mdns(mdns::Event),
}

impl From<ping::Event> for BeaconEvent {
    fn from(event: ping::Event) -> Self {
        BeaconEvent::Ping(event)
    }
}

impl From<identify::Event> for BeaconEvent {
    fn from(event: identify::Event) -> Self {
        BeaconEvent::Identify(event)
    }
}

impl From<gossipsub::Event> for BeaconEvent {
    fn from(event: gossipsub::Event) -> Self {
        BeaconEvent::Gossipsub(event)
    }
}

impl From<mdns::Event> for BeaconEvent {
    fn from(event: mdns::Event) -> Self {
        BeaconEvent::Mdns(event)
    }
}

#[derive(Debug)]
pub enum NetworkCommand {
    Broadcast(String),
    Private(String, PeerId),
}

pub struct BeaconNetwork {
    swarm: libp2p::Swarm<BeaconBehaviour>,
    message_sender: mpsc::UnboundedSender<NetworkCommand>,
    message_receiver: mpsc::UnboundedReceiver<NetworkCommand>,
    peer_id: PeerId,
}

impl BeaconNetwork {
    pub async fn new() -> Result<Self, Box<dyn Error>> {
        // Create a random key for ourselves
        let id_keys = identity::Keypair::generate_ed25519();
        let peer_id = PeerId::from(id_keys.public());
        info!("Local peer id: {peer_id}");
        
        let local_peer_id = peer_id;

        // Set up Gossipsub
        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(std::time::Duration::from_secs(1))
            .validation_mode(gossipsub::ValidationMode::Strict)
            .message_id_fn(|message: &gossipsub::Message| {
                let mut s = DefaultHasher::new();
                message.data.as_slice().hash(&mut s);
                gossipsub::MessageId::from(s.finish().to_string())
            })
            .build()
            .expect("Valid config");

        // Build the swarm
        let swarm = libp2p::SwarmBuilder::with_existing_identity(id_keys)
            .with_tokio()
            .with_tcp(
                libp2p::tcp::Config::default(),
                libp2p::tls::Config::new,
                libp2p::yamux::Config::default,
            )?
            .with_behaviour(|key| {
                Ok(BeaconBehaviour {
                    ping: ping::Behaviour::new(ping::Config::new()),
                    identify: identify::Behaviour::new(identify::Config::new(
                        "beacon/1.0.0".into(),
                        key.public(),
                    )),
                    mdns: mdns::tokio::Behaviour::new(mdns::Config::default(), peer_id)?,
                    gossipsub: gossipsub::Behaviour::new(
                        gossipsub::MessageAuthenticity::Signed(key.clone()),
                        gossipsub_config,
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
            peer_id: local_peer_id,
        })
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn Error>> {
        // Listen on all interfaces
        let addr: Multiaddr = "/ip4/0.0.0.0/tcp/0".parse()?;
        self.swarm.listen_on(addr)?;

        // Subscribe to both broadcast and private message topics
        let broadcast_topic = gossipsub::IdentTopic::new("beacon-broadcasts");
        let private_topic = gossipsub::IdentTopic::new("beacon-messages");
        
        self.swarm.behaviour_mut().gossipsub.subscribe(&broadcast_topic)?;
        self.swarm.behaviour_mut().gossipsub.subscribe(&private_topic)?;

        loop {
            tokio::select! {
                event = self.swarm.select_next_some() => {
                    match event {
                        libp2p::swarm::SwarmEvent::Behaviour(BeaconEvent::Gossipsub(
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
                                }
                            }
                        }
                        libp2p::swarm::SwarmEvent::Behaviour(BeaconEvent::Mdns(mdns::Event::Discovered(peers))) => {
                            for (peer_id, _addr) in peers {
                                info!("Discovered peer: {peer_id}");
                                self.swarm.behaviour_mut()
                                    .gossipsub
                                    .add_explicit_peer(&peer_id);
                            }
                        }
                        libp2p::swarm::SwarmEvent::NewListenAddr { address, .. } => {
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