use libp2p::PeerId;

#[derive(Debug)]
pub enum NetworkCommand {
    Broadcast(String),
    Private(String, PeerId),
}