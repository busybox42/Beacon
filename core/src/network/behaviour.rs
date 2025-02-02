use libp2p::{
    gossipsub,
    identify,
    mdns,
    ping,
    swarm::NetworkBehaviour,
};

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "BeaconEvent")]
pub struct BeaconBehaviour {
    pub ping: ping::Behaviour,
    pub identify: identify::Behaviour,
    pub gossipsub: gossipsub::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
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