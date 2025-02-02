// This file is currently empty or not implemented yet.
// We could add types like:

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct UserProfile {
    pub peer_id: String,
    pub display_name: Option<String>,
    pub status: UserStatus,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum UserStatus {
    Online,
    Away,
    Offline,
}