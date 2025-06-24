use anyhow::Result;
use arboard::Clipboard;
use kyra_core::{DaemonConfig, Message, Packet};
use serde_json;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};
use tokio::net::{TcpListener as TokioTcpListener, TcpStream as TokioTcpStream};
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};
use tracing_subscriber::fmt;

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
    // Load configuration
    let config = DaemonConfig::load()?;

    // Initialize logging
    init_logging(&config)?;

    info!("Starting Kyra Daemon...");
    info!("Configuration loaded: {:?}", config);

    let addr = format!("{}:{}", config.network.host, config.network.port);
    let listener = TokioTcpListener::bind(&addr).await?;

    info!("Daemon listening on {}", addr);

    let active_transfers: ActiveTransfers = Arc::new(Mutex::new(HashMap::new()));

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                info!("New connection from: {}", addr);
                let transfers = active_transfers.clone();
                let config = config.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, transfers, config).await {
                        error!("Error handling connection from {}: {}", addr, e);
                    }
                });
            }
            Err(e) => {
                error!("Error accepting connection: {}", e);
            }
        }
    }
}

fn init_logging(config: &DaemonConfig) -> Result<()> {
    let subscriber = fmt()
        .with_target(false)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true);

    if let Some(log_file) = &config.logging.file {
        if let Some(parent) = log_file.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_file)?;
        subscriber.with_writer(file).init();
    } else {
        subscriber.init();
    }

    Ok(())
}

async fn handle_connection(
    stream: TokioTcpStream,
    active_transfers: ActiveTransfers,
    config: DaemonConfig,
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

    info!("Client connected with ID: {}", client_id);

    loop {
        line.clear();
        match reader.read_line(&mut line).await? {
            0 => {
                info!("Client disconnected: {}", peer_addr);
                // Clean up any active transfers for this client
                let mut transfers = active_transfers.lock().await;
                if transfers.remove(&client_id).is_some() {
                    warn!("Cleaned up incomplete transfer for client: {}", client_id);
                }
                break;
            }
            _ => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }

                debug!("Raw message from {}: {}", peer_addr, trimmed);

                match serde_json::from_str::<Packet>(trimmed) {
                    Ok(packet) => {
                        debug!("Received packet from {}: {:?}", peer_addr, packet.message);

                        let response = match handle_message(
                            packet.message,
                            &client_id,
                            &active_transfers,
                            &config,
                        )
                        .await
                        {
                            Ok(response_msg) => response_msg,
                            Err(e) => {
                                error!("Error handling message from {}: {}", peer_addr, e);
                                Some(Packet::error(format!("Error: {}", e)))
                            }
                        };

                        if let Some(response) = response {
                            let response_json = serde_json::to_string(&response)?;
                            // Handle broken pipe gracefully
                            if let Err(e) = write_half.write_all(response_json.as_bytes()).await {
                                if e.kind() == std::io::ErrorKind::BrokenPipe {
                                    info!("Client {} disconnected during response", peer_addr);
                                    break;
                                }
                                return Err(e.into());
                            }
                            if let Err(e) = write_half.write_all(b"\n").await {
                                if e.kind() == std::io::ErrorKind::BrokenPipe {
                                    info!("Client {} disconnected during response", peer_addr);
                                    break;
                                }
                                return Err(e.into());
                            }
                            if let Err(e) = write_half.flush().await {
                                if e.kind() == std::io::ErrorKind::BrokenPipe {
                                    info!("Client {} disconnected during response", peer_addr);
                                    break;
                                }
                                return Err(e.into());
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to deserialize message from {}: {}", peer_addr, e);
                        let error_packet = Packet::error(format!("Invalid message format: {}", e));
                        let error_json = serde_json::to_string(&error_packet)?;
                        // Handle broken pipe gracefully
                        if let Err(write_err) = write_half.write_all(error_json.as_bytes()).await {
                            if write_err.kind() == std::io::ErrorKind::BrokenPipe {
                                info!("Client {} disconnected during error response", peer_addr);
                                break;
                            }
                            return Err(write_err.into());
                        }
                        if let Err(write_err) = write_half.write_all(b"\n").await {
                            if write_err.kind() == std::io::ErrorKind::BrokenPipe {
                                info!("Client {} disconnected during error response", peer_addr);
                                break;
                            }
                            return Err(write_err.into());
                        }
                        if let Err(write_err) = write_half.flush().await {
                            if write_err.kind() == std::io::ErrorKind::BrokenPipe {
                                info!("Client {} disconnected during error response", peer_addr);
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
    config: &DaemonConfig,
) -> Result<Option<Packet>> {
    match message {
        Message::Ping => {
            debug!("Received Ping from {}, sending Pong", client_id);
            Ok(Some(Packet::pong()))
        }
        Message::Pong => {
            debug!("Received Pong from {}", client_id);
            Ok(None)
        }
        Message::FileMetadata { name, size } => {
            info!(
                "Starting file transfer from {}: {} ({} bytes)",
                client_id, name, size
            );

            // Use configured download directory
            let downloads_dir = &config.storage.download_dir;
            std::fs::create_dir_all(downloads_dir)?;

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

            info!("Ready to receive file: {} -> {:?}", name, file_path);
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
                debug!(
                    "Received chunk for {} from {}: {} / {} bytes ({:.1}%)",
                    transfer.name, client_id, transfer.received, transfer.size, progress
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
                    info!(
                        "File transfer completed successfully from {}: {} ({} bytes)",
                        client_id, transfer.name, transfer.received
                    );
                    Ok(Some(Packet::pong()))
                } else {
                    warn!(
                        "File transfer completed with size mismatch from {}: {} (expected: {}, received: {})",
                        client_id, transfer.name, transfer.size, transfer.received
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
            info!(
                "Received clipboard text from {}: {} characters",
                client_id,
                text.len()
            );
            debug!("Clipboard content: {}", text);

            match Clipboard::new() {
                Ok(mut clipboard) => {
                    if let Err(e) = clipboard.set_text(text) {
                        error!("Failed to set clipboard: {}", e);
                        return Ok(Some(Packet::error(format!(
                            "Failed to set clipboard: {}",
                            e
                        ))));
                    }
                    info!("Clipboard text set successfully");

                    if let Err(e) = notifica::notify("Kyra", "Clipboard text updated!") {
                        warn!("Failed to send notification: {}", e);
                    }

                    Ok(Some(Packet::pong()))
                }
                Err(e) => {
                    error!("Failed to access clipboard: {}", e);
                    Ok(Some(Packet::error(format!(
                        "Failed to access clipboard: {}",
                        e
                    ))))
                }
            }
        }
        Message::Error(ref err) => {
            warn!("Received Error from {}: {}", client_id, err);
            Ok(None)
        }
    }
}
