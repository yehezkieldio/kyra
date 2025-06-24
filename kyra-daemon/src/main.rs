use anyhow::Result;
use arboard::Clipboard;
use kyra_core::{DEFAULT_HOST, DEFAULT_PORT, Message, Packet};
use serde_json;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};
use tokio::net::{TcpListener as TokioTcpListener, TcpStream as TokioTcpStream};
use tokio::sync::Mutex;

#[derive(Debug)]
struct FileTransfer {
    name: String,
    size: u64,
    received: u64,
    file: File,
}

type ActiveTransfers = Arc<Mutex<HashMap<String, FileTransfer>>>;

#[tokio::main]
async fn main() -> Result<()> {
    println!("Starting Kyra Daemon...");

    let addr = format!("{}:{}", DEFAULT_HOST, DEFAULT_PORT);
    let listener = TokioTcpListener::bind(&addr).await?;

    println!("Daemon listening on {}", addr);

    let active_transfers: ActiveTransfers = Arc::new(Mutex::new(HashMap::new()));

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                println!("New connection from: {}", addr);
                let transfers = active_transfers.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, transfers).await {
                        eprintln!("Error handling connection: {}", e);
                    }
                });
            }
            Err(e) => {
                eprintln!("Error accepting connection: {}", e);
            }
        }
    }
}

async fn handle_connection(
    stream: TokioTcpStream,
    active_transfers: ActiveTransfers,
) -> Result<()> {
    let peer_addr = stream.peer_addr()?;
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = TokioBufReader::new(read_half);
    let mut line = String::new();
    let client_id = format!(
        "{}_{}",
        peer_addr,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    );

    loop {
        line.clear();
        match reader.read_line(&mut line).await? {
            0 => {
                println!("Client disconnected: {}", peer_addr);
                // Clean up any active transfers for this client
                let mut transfers = active_transfers.lock().await;
                transfers.remove(&client_id);
                break;
            }
            _ => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }

                match serde_json::from_str::<Packet>(trimmed) {
                    Ok(packet) => {
                        println!("Received packet from {}: {:?}", peer_addr, packet);

                        let response =
                            match handle_message(packet.message, &client_id, &active_transfers)
                                .await
                            {
                                Ok(response_msg) => response_msg,
                                Err(e) => {
                                    eprintln!("Error handling message from {}: {}", peer_addr, e);
                                    Some(Packet::error(format!("Error: {}", e)))
                                }
                            };

                        if let Some(response) = response {
                            let response_json = serde_json::to_string(&response)?;
                            // Handle broken pipe gracefully
                            if let Err(e) = write_half.write_all(response_json.as_bytes()).await {
                                if e.kind() == std::io::ErrorKind::BrokenPipe {
                                    println!("Client {} disconnected during response", peer_addr);
                                    break;
                                }
                                return Err(e.into());
                            }
                            if let Err(e) = write_half.write_all(b"\n").await {
                                if e.kind() == std::io::ErrorKind::BrokenPipe {
                                    println!("Client {} disconnected during response", peer_addr);
                                    break;
                                }
                                return Err(e.into());
                            }
                            if let Err(e) = write_half.flush().await {
                                if e.kind() == std::io::ErrorKind::BrokenPipe {
                                    println!("Client {} disconnected during response", peer_addr);
                                    break;
                                }
                                return Err(e.into());
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to deserialize message from {}: {}", peer_addr, e);
                        let error_packet = Packet::error(format!("Invalid message format: {}", e));
                        let error_json = serde_json::to_string(&error_packet)?;
                        // Handle broken pipe gracefully
                        if let Err(write_err) = write_half.write_all(error_json.as_bytes()).await {
                            if write_err.kind() == std::io::ErrorKind::BrokenPipe {
                                println!("Client {} disconnected during error response", peer_addr);
                                break;
                            }
                            return Err(write_err.into());
                        }
                        if let Err(write_err) = write_half.write_all(b"\n").await {
                            if write_err.kind() == std::io::ErrorKind::BrokenPipe {
                                println!("Client {} disconnected during error response", peer_addr);
                                break;
                            }
                            return Err(write_err.into());
                        }
                        if let Err(write_err) = write_half.flush().await {
                            if write_err.kind() == std::io::ErrorKind::BrokenPipe {
                                println!("Client {} disconnected during error response", peer_addr);
                                break;
                            }
                            return Err(write_err.into());
                        }
                    }
                }
            }
        }
    }

    // Clean up transfers when connection ends
    let mut transfers = active_transfers.lock().await;
    transfers.remove(&client_id);

    Ok(())
}

async fn handle_message(
    message: Message,
    client_id: &str,
    active_transfers: &ActiveTransfers,
) -> Result<Option<Packet>> {
    match message {
        Message::Ping => {
            println!("Received Ping, sending Pong");
            Ok(Some(Packet::pong()))
        }
        Message::Pong => {
            println!("Received Pong");
            Ok(None)
        }
        Message::FileMetadata { name, size } => {
            println!("Starting file transfer: {} ({} bytes)", name, size);

            // Create downloads directory if it doesn't exist
            let downloads_dir = PathBuf::from("downloads");
            std::fs::create_dir_all(&downloads_dir)?;

            // Create file path
            let file_path = downloads_dir.join(&name);

            // Create/truncate the file
            let file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&file_path)?;

            // Store the transfer info
            let transfer = FileTransfer {
                name: name.clone(),
                size,
                received: 0,
                file,
            };

            let mut transfers = active_transfers.lock().await;
            transfers.insert(client_id.to_string(), transfer);

            println!("Ready to receive file: {} -> {:?}", name, file_path);
            Ok(Some(Packet::pong())) // Acknowledge metadata
        }
        Message::FileChunk(data) => {
            let mut transfers = active_transfers.lock().await;

            if let Some(transfer) = transfers.get_mut(client_id) {
                // Write chunk to file
                transfer.file.write_all(&data)?;
                transfer.file.flush()?;
                transfer.received += data.len() as u64;

                let progress = (transfer.received as f64 / transfer.size as f64) * 100.0;
                println!(
                    "Received chunk for {}: {} / {} bytes ({:.1}%)",
                    transfer.name, transfer.received, transfer.size, progress
                );

                Ok(None) // Don't send response for chunks
            } else {
                Err(anyhow::anyhow!("No active file transfer for this client"))
            }
        }
        Message::FileComplete => {
            let mut transfers = active_transfers.lock().await;

            if let Some(transfer) = transfers.remove(client_id) {
                // Flush and close file
                drop(transfer.file);

                if transfer.received == transfer.size {
                    println!(
                        "File transfer completed successfully: {} ({} bytes)",
                        transfer.name, transfer.received
                    );
                    Ok(Some(Packet::pong()))
                } else {
                    println!(
                        "File transfer completed with size mismatch: {} (expected: {}, received: {})",
                        transfer.name, transfer.size, transfer.received
                    );
                    Ok(Some(Packet::error(format!(
                        "Size mismatch: expected {}, received {}",
                        transfer.size, transfer.received
                    ))))
                }
            } else {
                Err(anyhow::anyhow!("No active file transfer to complete"))
            }
        }
        Message::ClipboardText(text) => {
            println!("Received clipboard text: {} characters", text.len());
            println!("Clipboard content: {}", text);

            let mut clipboard = Clipboard::new().unwrap();
            clipboard.set_text(text).unwrap();
            println!("Clipboard text set successfully");

            notifica::notify("Kyra", "Clipboard text updated!").unwrap();

            Ok(None)
        }
        Message::Error(ref err) => {
            println!("Received Error: {}", err);
            Ok(None)
        }
    }
}
