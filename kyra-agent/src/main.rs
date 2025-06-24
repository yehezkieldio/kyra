use anyhow::{Context, Result};
use clap::{Arg, Command};
use kyra_core::{AgentConfig, CHUNK_SIZE, DiscoveryService, Message, Packet, generate_auth_token};
use serde_json;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};
use tokio::net::TcpStream;
use tracing::{debug, error, info, warn};
use tracing_subscriber::fmt;

#[tokio::main]
async fn main() -> Result<()> {
    let matches = build_cli().get_matches();

    // Load configuration
    let config = AgentConfig::load()?;

    // Initialize logging
    init_logging(&config)?;

    match matches.subcommand() {
        Some(("discover", _)) => {
            discover_peers(&config).await?;
        }
        Some(("ping", ping_matches)) => {
            let host = ping_matches.get_one::<String>("host");
            send_ping(&config, host).await?;
        }
        Some(("send", send_matches)) => match send_matches.subcommand() {
            Some(("file", file_matches)) => {
                let file_path = file_matches.get_one::<String>("path").unwrap();
                let host = file_matches.get_one::<String>("host");
                send_file(file_path, &config, host).await?;
            }
            Some(("clipboard", clipboard_matches)) => {
                let host = clipboard_matches.get_one::<String>("host");
                send_clipboard(&config, host).await?;
            }
            Some(("text", text_matches)) => {
                let message = text_matches.get_one::<String>("message").unwrap();
                let host = text_matches.get_one::<String>("host");
                send_text_message(message, &config, host).await?;
            }
            _ => {
                error!("No valid send subcommand specified. Use 'file', 'clipboard', or 'text'");
            }
        },
        Some(("auth", auth_matches)) => match auth_matches.subcommand() {
            Some(("generate-token", token_matches)) => {
                let passphrase = token_matches.get_one::<String>("passphrase").unwrap();
                generate_token(passphrase)?;
            }
            _ => {
                error!("No valid auth subcommand specified. Use 'generate-token'");
            }
        },
        _ => {
            error!("No command specified. Use --help for usage information");
        }
    }

    Ok(())
}

fn build_cli() -> Command {
    Command::new("kyra-agent")
        .version("0.1.0")
        .about("Kyra Agent - Secure cross-platform data transfer client")
        .subcommand(Command::new("discover").about("Discover Kyra peers on the network"))
        .subcommand(
            Command::new("ping")
                .about("Send a ping to test connectivity")
                .arg(
                    Arg::new("host")
                        .help("Specific host to ping (optional, will use discovery)")
                        .long("host")
                        .value_name("HOST"),
                ),
        )
        .subcommand(
            Command::new("send")
                .about("Send data to a peer")
                .subcommand(
                    Command::new("file")
                        .about("Send a file")
                        .arg(
                            Arg::new("path")
                                .help("Path to the file to send")
                                .required(true)
                                .index(1),
                        )
                        .arg(
                            Arg::new("host")
                                .help("Target host")
                                .long("host")
                                .value_name("HOST"),
                        ),
                )
                .subcommand(
                    Command::new("clipboard")
                        .about("Send clipboard content")
                        .arg(
                            Arg::new("host")
                                .help("Target host")
                                .long("host")
                                .value_name("HOST"),
                        ),
                )
                .subcommand(
                    Command::new("text")
                        .about("Send text message")
                        .arg(
                            Arg::new("message")
                                .help("Text message to send")
                                .required(true)
                                .index(1),
                        )
                        .arg(
                            Arg::new("host")
                                .help("Target host")
                                .long("host")
                                .value_name("HOST"),
                        ),
                ),
        )
        .subcommand(
            Command::new("auth")
                .about("Authentication utilities")
                .subcommand(
                    Command::new("generate-token")
                        .about("Generate authentication token from passphrase")
                        .arg(
                            Arg::new("passphrase")
                                .help("Passphrase to generate token from")
                                .required(true)
                                .index(1),
                        ),
                ),
        )
}

fn init_logging(config: &AgentConfig) -> Result<()> {
    let subscriber = fmt()
        .with_target(false)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false);

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

async fn send_ping(config: &AgentConfig, host: Option<&String>) -> Result<()> {
    info!("Starting Kyra Agent - Ping...");

    let target_host = host.map(|h| h.as_str()).unwrap_or(&config.network.host);
    let addr = format!("{}:{}", target_host, config.network.port);
    info!("Connecting to daemon at {}", addr);

    let mut stream = TcpStream::connect(&addr)
        .await
        .context("Failed to connect to daemon")?;
    info!("Connected to daemon!");

    // Send ping
    let ping_packet = Packet::ping();
    send_packet(&mut stream, &ping_packet).await?;
    debug!("Sent ping: {:?}", ping_packet);

    // Wait for response
    let response = receive_packet(&mut stream).await?;
    match response.message {
        Message::Pong => info!("Successfully received Pong!"),
        Message::Error(err) => error!("Daemon returned error: {}", err),
        _ => warn!("Unexpected response: {:?}", response.message),
    }

    Ok(())
}

async fn send_file(file_path: &str, config: &AgentConfig, host: Option<&String>) -> Result<()> {
    info!("Starting Kyra Agent - File Transfer...");

    let path = Path::new(file_path);
    if !path.exists() {
        return Err(anyhow::anyhow!("File does not exist: {}", file_path));
    }

    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .context("Invalid file name")?
        .to_string();

    let file_size = path
        .metadata()
        .context("Failed to get file metadata")?
        .len();

    info!("Sending file: {} ({} bytes)", file_name, file_size);

    let target_host = host.map(|h| h.as_str()).unwrap_or(&config.network.host);
    let addr = format!("{}:{}", target_host, config.network.port);
    let mut stream = TcpStream::connect(&addr)
        .await
        .context("Failed to connect to daemon")?;
    info!("Connected to daemon!");

    // Send file metadata
    let metadata_packet = Packet::file_metadata(file_name.clone(), file_size, None, false);
    send_packet(&mut stream, &metadata_packet).await?;
    info!("Sent file metadata: {} ({} bytes)", file_name, file_size);

    // Wait for acknowledgment
    let (reader, mut writer) = stream.split();
    let mut reader = TokioBufReader::new(reader);
    let mut response = String::new();
    reader
        .read_line(&mut response)
        .await
        .context("Failed to read response")?;
    let trimmed = response.trim();
    let ack_response =
        serde_json::from_str::<Packet>(trimmed).context("Failed to deserialize response")?;

    match ack_response.message {
        Message::Pong => info!("Metadata acknowledged"),
        Message::Error(err) => return Err(anyhow::anyhow!("Daemon error: {}", err)),
        _ => {
            return Err(anyhow::anyhow!(
                "Unexpected response: {:?}",
                ack_response.message
            ));
        }
    }

    // Open file and send chunks
    let mut file = File::open(path).context("Failed to open file")?;
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut bytes_sent = 0u64;
    let mut sequence = 0u64;
    let total_chunks = (file_size + CHUNK_SIZE as u64 - 1) / CHUNK_SIZE as u64; // Calculate total chunks

    loop {
        let bytes_read = file.read(&mut buffer).context("Failed to read file")?;

        if bytes_read == 0 {
            break; // EOF
        }

        let chunk = buffer[..bytes_read].to_vec();
        let chunk_packet = Packet::file_chunk(chunk, sequence, total_chunks);
        // Send chunk directly to writer without using send_packet
        let json = serde_json::to_string(&chunk_packet).context("Failed to serialize chunk")?;
        writer
            .write_all(json.as_bytes())
            .await
            .context("Failed to write chunk")?;
        writer
            .write_all(b"\n")
            .await
            .context("Failed to write newline")?;
        writer.flush().await.context("Failed to flush stream")?;

        bytes_sent += bytes_read as u64;
        sequence += 1;
        let progress = (bytes_sent as f64 / file_size as f64) * 100.0;
        debug!(
            "Sent chunk: {} / {} bytes ({:.1}%)",
            bytes_sent, file_size, progress
        );
    }

    // Send completion signal
    let complete_packet = Packet::file_complete(None);
    let json = serde_json::to_string(&complete_packet).context("Failed to serialize completion")?;
    writer
        .write_all(json.as_bytes())
        .await
        .context("Failed to write completion")?;
    writer
        .write_all(b"\n")
        .await
        .context("Failed to write newline")?;
    writer.flush().await.context("Failed to flush stream")?;

    // Wait for final acknowledgment
    response.clear();
    reader
        .read_line(&mut response)
        .await
        .context("Failed to read final response")?;
    let trimmed = response.trim();
    let final_response =
        serde_json::from_str::<Packet>(trimmed).context("Failed to deserialize final response")?;

    match final_response.message {
        Message::Pong => info!("File transfer completed successfully!"),
        Message::Error(err) => return Err(anyhow::anyhow!("Daemon error: {}", err)),
        _ => {
            return Err(anyhow::anyhow!(
                "Unexpected response: {:?}",
                final_response.message
            ));
        }
    }

    Ok(())
}

async fn discover_peers(_config: &AgentConfig) -> Result<()> {
    info!("Starting peer discovery...");

    let mut discovery = DiscoveryService::new("kyra-agent".to_string())?;
    let peers = discovery.discover_peers(Duration::from_secs(5)).await?;

    if peers.is_empty() {
        info!("No Kyra peers found on the network");
    } else {
        info!("Found {} Kyra peer(s):", peers.len());
        for peer in peers {
            info!("  - {} at {}:{}", peer.name, peer.host, peer.port);
        }
    }

    Ok(())
}

async fn send_text_message(
    message: &str,
    config: &AgentConfig,
    host: Option<&String>,
) -> Result<()> {
    info!("Starting Kyra Agent - Text Message...");

    let target_host = host.map(|h| h.as_str()).unwrap_or(&config.network.host);
    let addr = format!("{}:{}", target_host, config.network.port);
    let mut stream = TcpStream::connect(&addr)
        .await
        .context("Failed to connect to daemon")?;
    info!("Connected to daemon at {}!", addr);

    let text_packet = Packet::text_message(message.to_string());
    send_packet(&mut stream, &text_packet).await?;
    info!("Sent text message ({} characters)", message.len());

    // Wait for acknowledgment
    let response = receive_packet(&mut stream).await?;
    match response.message {
        Message::Pong => info!("Text message sent successfully!"),
        Message::Error(err) => error!("Daemon returned error: {}", err),
        _ => warn!("Unexpected response: {:?}", response.message),
    }

    Ok(())
}

async fn send_clipboard(config: &AgentConfig, host: Option<&String>) -> Result<()> {
    info!("Starting Kyra Agent - Clipboard Transfer...");

    // Try to get clipboard content
    let clipboard_text = get_clipboard_content()?;
    if clipboard_text.is_empty() {
        return Err(anyhow::anyhow!("Clipboard is empty"));
    }

    let target_host = host.map(|h| h.as_str()).unwrap_or(&config.network.host);
    let addr = format!("{}:{}", target_host, config.network.port);
    let mut stream = TcpStream::connect(&addr)
        .await
        .context("Failed to connect to daemon")?;
    info!("Connected to daemon at {}!", addr);

    let clipboard_packet = Packet::clipboard_text(clipboard_text.clone());
    send_packet(&mut stream, &clipboard_packet).await?;
    info!("Sent clipboard text ({} characters)", clipboard_text.len());

    // Wait for acknowledgment
    let response = receive_packet(&mut stream).await?;
    match response.message {
        Message::Pong => info!("Clipboard text sent successfully!"),
        Message::Error(err) => error!("Daemon returned error: {}", err),
        _ => warn!("Unexpected response: {:?}", response.message),
    }

    Ok(())
}

fn get_clipboard_content() -> Result<String> {
    // Try different clipboard commands based on the system
    use std::process::Command;

    // Try xclip first (common on Linux)
    if let Ok(output) = Command::new("xclip")
        .args(&["-selection", "clipboard", "-o"])
        .output()
    {
        if output.status.success() {
            return Ok(String::from_utf8_lossy(&output.stdout).to_string());
        }
    }

    // Try xsel as alternative
    if let Ok(output) = Command::new("xsel")
        .args(&["--clipboard", "--output"])
        .output()
    {
        if output.status.success() {
            return Ok(String::from_utf8_lossy(&output.stdout).to_string());
        }
    }

    // Try wl-paste for Wayland
    if let Ok(output) = Command::new("wl-paste").output() {
        if output.status.success() {
            return Ok(String::from_utf8_lossy(&output.stdout).to_string());
        }
    }

    // Try pbpaste for macOS
    if let Ok(output) = Command::new("pbpaste").output() {
        if output.status.success() {
            return Ok(String::from_utf8_lossy(&output.stdout).to_string());
        }
    }

    Err(anyhow::anyhow!(
        "Unable to access clipboard. Please install xclip, xsel, wl-paste, or pbpaste"
    ))
}

fn generate_token(passphrase: &str) -> Result<()> {
    let token = generate_auth_token(passphrase);
    println!("Generated authentication token:");
    println!("{}", token);
    println!("\nThis token can be used for secure authentication between Kyra instances.");
    Ok(())
}

async fn send_packet(stream: &mut TcpStream, packet: &Packet) -> Result<()> {
    let json = serde_json::to_string(packet).context("Failed to serialize packet")?;
    stream
        .write_all(json.as_bytes())
        .await
        .context("Failed to write packet")?;
    stream
        .write_all(b"\n")
        .await
        .context("Failed to write newline")?;
    stream.flush().await.context("Failed to flush stream")?;
    Ok(())
}

async fn receive_packet(stream: &mut TcpStream) -> Result<Packet> {
    let mut reader = TokioBufReader::new(stream);
    let mut response = String::new();

    reader
        .read_line(&mut response)
        .await
        .context("Failed to read response")?;

    let trimmed = response.trim();
    serde_json::from_str::<Packet>(trimmed).context("Failed to deserialize response")
}
