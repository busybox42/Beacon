// src/identity/mod.rs
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::RwLock;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserProfile {
    pub username: String,
    pub peer_id: PeerId,
    pub public_key: Vec<u8>,
    pub last_seen: u64,
}

pub struct IdentityManager {
    profiles: RwLock<HashMap<PeerId, UserProfile>>,
    username_to_peer: RwLock<HashMap<String, PeerId>>,
}

impl IdentityManager {
    pub fn new() -> Self {
        Self {
            profiles: RwLock::new(HashMap::new()),
            username_to_peer: RwLock::new(HashMap::new()),
        }
    }

    pub async fn register_username(&self, username: String, peer_id: PeerId, public_key: Vec<u8>) -> Result<(), IdentityError> {
        let mut profiles = self.profiles.write().await;
        let mut username_map = self.username_to_peer.write().await;

        // Check if username is taken
        if username_map.contains_key(&username) {
            return Err(IdentityError::UsernameTaken);
        }

        let profile = UserProfile {
            username: username.clone(),
            peer_id,
            public_key,
            last_seen: chrono::Utc::now().timestamp() as u64,
        };

        profiles.insert(peer_id, profile);
        username_map.insert(username, peer_id);
        Ok(())
    }

    pub async fn search_users(&self, query: &str) -> Vec<UserProfile> {
        let profiles = self.profiles.read().await;
        profiles
            .values()
            .filter(|profile| profile.username.to_lowercase().contains(&query.to_lowercase()))
            .cloned()
            .collect()
    }

    pub async fn get_profile_by_username(&self, username: &str) -> Option<UserProfile> {
        let username_map = self.username_to_peer.read().await;
        let profiles = self.profiles.read().await;
        
        username_map.get(username)
            .and_then(|peer_id| profiles.get(peer_id))
            .cloned()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("Username is already taken")]
    UsernameTaken,
}