use beacon_core::{BeaconNetwork, NetworkCommand};
use std::error::Error;
use tokio::io::{self, AsyncBufReadExt};
use tracing::info;
use libp2p::{PeerId, multiaddr::Protocol};
use std::str::FromStr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Create and start the network
    let mut network = BeaconNetwork::new().await?;
    let sender = network.sender();

    // Start the network task
    let network_task = tokio::spawn(async move {
        if let Err(e) = network.run().await {
            eprintln!("Network error: {e}");
        }
    });

    // Handle user input
    let stdin = io::stdin();
    let reader = io::BufReader::new(stdin);
    let mut lines = reader.lines();

    println!("Beacon P2P Chat");
    println!("Commands:");
    println!("  /msg <peer-id> <message> - Send private message");
    println!("  <message>                - Broadcast message");
    println!("Press Ctrl+C to exit");

    while let Some(line) = lines.next_line().await? {
        if !line.is_empty() {
            if line.starts_with("/msg ") {
                let parts: Vec<&str> = line.splitn(3, ' ').collect();
                if parts.len() == 3 {
                    if let Ok(peer_id) = PeerId::from_str(parts[1]) {
                        let message = parts[2].to_string();
                        info!("Sending private message to {}: {}", peer_id, message);
                        sender.send(NetworkCommand::Private(message, peer_id))?;
                    } else {
                        eprintln!("Invalid peer ID format");
                    }
                } else {
                    eprintln!("Usage: /msg <peer-id> <message>");
                }
            } else {
                info!("Broadcasting: {}", line);
                sender.send(NetworkCommand::Broadcast(line))?;
            }
        }
    }

    // Clean up
    network_task.abort();
    Ok(())
}