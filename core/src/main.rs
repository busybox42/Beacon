use beacon_core::{BeaconNetwork, NetworkCommand};
use std::error::Error;
use tokio::io::{self, AsyncBufReadExt};
use tracing::info;
use libp2p::PeerId;
use std::str::FromStr;
use tokio::sync::mpsc::UnboundedSender;

// Define available commands and their help text
const COMMANDS: &[(&str, &str)] = &[
    ("/help", "Show this help message"),
    ("/broadcast <message>", "Broadcast a message to all peers"),
    ("/msg <peer-id> <message>", "Send a private message to a specific peer"),
    ("/quit", "Exit the application"),
];

fn print_help() {
    println!("Beacon P2P Chat Commands:");
    for (cmd, desc) in COMMANDS {
        println!("  {:<25} - {}", cmd, desc);
    }
}

// Modified to return a bool indicating whether to quit
fn handle_command(line: String, sender: &UnboundedSender<NetworkCommand>) -> Result<bool, Box<dyn Error>> {
    let trimmed = line.trim();
    
    match trimmed {
        "" => Ok(false),
        "/help" => {
            print_help();
            Ok(false)
        }
        "/quit" => {
            println!("Exiting Beacon...");
            Ok(true)
        }
        line if line.starts_with("/broadcast ") => {
            let message = line.trim_start_matches("/broadcast ").to_string();
            if !message.is_empty() {
                info!("Broadcasting: {}", message);
                sender.send(NetworkCommand::Broadcast(message))?;
            } else {
                eprintln!("Usage: /broadcast <message>");
            }
            Ok(false)
        }
        line if line.starts_with("/msg ") => {
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
            Ok(false)
        }
        line if line.starts_with('/') => {
            eprintln!("Unknown command. Type /help for available commands.");
            Ok(false)
        }
        _ => {
            eprintln!("Invalid command format. Use /broadcast <message> to broadcast or type /help for available commands.");
            Ok(false)
        }
    }
}

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

    println!("Welcome to Beacon P2P Chat");
    println!("Type /help to see available commands");
    println!("Press Ctrl+C to exit");
    println!();

    while let Some(line) = lines.next_line().await? {
        match handle_command(line, &sender) {
            Ok(true) => break, // Exit the loop if quit command was issued
            Ok(false) => continue,
            Err(e) => eprintln!("Error: {}", e),
        }
    }

    // Clean up
    network_task.abort();
    println!("Goodbye!");
    Ok(())
}