use libp2p::PeerId;
use tracing::info;
use libp2p::swarm::Swarm;
use crate::network::behaviour::BeaconBehaviour;

pub struct PeerDiscovery;

impl PeerDiscovery {
    pub fn handle_peer_discovered(
        swarm: &mut Swarm<BeaconBehaviour>,
        peer_id: PeerId,
    ) {
        info!("Discovered peer: {peer_id}");
        swarm.behaviour_mut()
            .gossipsub
            .add_explicit_peer(&peer_id);
    }

    #[allow(dead_code)]
    pub fn handle_peer_expired(
        swarm: &mut Swarm<BeaconBehaviour>,
        peer_id: PeerId,
    ) {
        info!("Peer expired: {peer_id}");
        swarm.behaviour_mut()
            .gossipsub
            .remove_explicit_peer(&peer_id);
    }
}