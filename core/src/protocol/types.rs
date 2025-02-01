use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub id: String,
    #[serde(serialize_with = "serialize_peer_id", deserialize_with = "deserialize_peer_id")]
    pub sender: PeerId,
    #[serde(serialize_with = "serialize_peer_id_vec", deserialize_with = "deserialize_peer_id_vec")]
    pub recipients: Vec<PeerId>,
    pub content: MessageContent,
    pub timestamp: SystemTime,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageContent {
    Text(String),
    Binary(Vec<u8>),
}

fn serialize_peer_id<S>(peer_id: &PeerId, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    peer_id.to_string().serialize(serializer)
}

fn deserialize_peer_id<'de, D>(deserializer: D) -> Result<PeerId, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    PeerId::from_str(&s).map_err(serde::de::Error::custom)
}

fn serialize_peer_id_vec<S>(peer_ids: &Vec<PeerId>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let strings: Vec<String> = peer_ids.iter().map(|p| p.to_string()).collect();
    strings.serialize(serializer)
}

fn deserialize_peer_id_vec<'de, D>(deserializer: D) -> Result<Vec<PeerId>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let strings = Vec::<String>::deserialize(deserializer)?;
    strings
        .into_iter()
        .map(|s| PeerId::from_str(&s).map_err(serde::de::Error::custom))
        .collect()
}