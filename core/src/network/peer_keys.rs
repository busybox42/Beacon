use std::collections::HashMap;
use libp2p::PeerId;
use x25519_dalek::PublicKey as X25519PublicKey;
use ed25519_dalek::VerifyingKey as Ed25519PublicKey;
use parking_lot::RwLock;

pub struct PeerKeyStore {
    keys: RwLock<HashMap<PeerId, PeerKeys>>,
}

#[derive(Clone)]
pub struct PeerKeys {
    pub x25519_public_key: X25519PublicKey,
    pub ed25519_public_key: Ed25519PublicKey,
}

impl PeerKeyStore {
    pub fn new() -> Self {
        PeerKeyStore {
            keys: RwLock::new(HashMap::new()),
        }
    }

    pub fn add_peer_keys(&self, peer_id: PeerId, x25519_key: X25519PublicKey, ed25519_key: Ed25519PublicKey) {
        let mut keys = self.keys.write();
        keys.insert(peer_id, PeerKeys {
            x25519_public_key: x25519_key,
            ed25519_public_key: ed25519_key,
        });
    }

    pub fn get_peer_keys(&self, peer_id: &PeerId) -> Option<PeerKeys> {
        self.keys.read().get(peer_id).cloned()
    }
}