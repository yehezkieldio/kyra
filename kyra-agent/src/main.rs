use anyhow::{Context, Result};
use clap::{Arg, Command};
use kyra_core::{AgentConfig, CHUNK_SIZE, Message, Packet};
use serde_json;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};
use tokio::net::TcpStream;
use tracing::{debug, error, info, warn};
use tracing_subscriber::fmt;

#[tokio::main]
async fn main() -> Result<()> {
    // Load configuration
    let config = AgentConfig::load()?;

    // Initialize logging
    init_logging(&config)?;

    let matches = Command::new("kyra-agent")
        .about("Kyra Agent - Client for data transfer")
        .subcommand(Command::new("ping").about("Send a ping to the daemon"))
        .subcommand(
            Command::new("send")
                .about("Send data")
                .subcommand(
                    Command::new("file").about("Send a file").arg(
                        Arg::new("path")
                            .help("Path to the file to send")
                            .required(true)
                            .index(1),
                    ),
                )
                .subcommand(
                    Command::new("clipboard").about("Send clipboard text").arg(
                        Arg::new("text")
                            .help("Text to send")
                            .required(true)
                            .index(1),
                    ),
                ),
        )
        .get_matches();

    match matches.subcommand() {
        Some(("ping", _)) => {
            send_ping(&config).await?;
        }
        Some(("send", send_matches)) => match send_matches.subcommand() {
            Some(("file", file_matches)) => {
                let file_path = file_matches.get_one::<String>("path").unwrap();
                send_file(file_path, &config).await?;
            }
            Some(("clipboard", clipboard_matches)) => {
                let text = clipboard_matches.get_one::<String>("text").unwrap();
                send_clipboard_text(text, &config).await?;
            }
            _ => {
                error!("Unknown send command. Use 'file' or 'clipboard'");
            }
        },
        _ => {
            error!("No command specified. Use 'ping' or 'send'");
        }
    }

    Ok(())
}

fn init_logging(config: &AgentConfig) -> Result<()> {
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

async fn send_ping(config: &AgentConfig) -> Result<()> {
    info!("Starting Kyra Agent - Ping...");

    let addr = format!("{}:{}", config.network.host, config.network.port);
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

async fn send_file(file_path: &str, config: &AgentConfig) -> Result<()> {
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

    let addr = format!("{}:{}", config.network.host, config.network.port);
    let mut stream = TcpStream::connect(&addr)
        .await
        .context("Failed to connect to daemon")?;
    info!("Connected to daemon!");

    // Send file metadata
    let metadata_packet = Packet::file_metadata(file_name.clone(), file_size);
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

    loop {
        let bytes_read = file.read(&mut buffer).context("Failed to read file")?;

        if bytes_read == 0 {
            break; // EOF
        }

        let chunk = buffer[..bytes_read].to_vec();
        let chunk_packet = Packet::file_chunk(chunk);
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
        let progress = (bytes_sent as f64 / file_size as f64) * 100.0;
        debug!(
            "Sent chunk: {} / {} bytes ({:.1}%)",
            bytes_sent, file_size, progress
        );
    }

    // Send completion signal
    let complete_packet = Packet::file_complete();
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

async fn send_clipboard_text(text: &str, config: &AgentConfig) -> Result<()> {
    info!("Starting Kyra Agent - Clipboard Transfer...");

    let addr = format!("{}:{}", config.network.host, config.network.port);
    let mut stream = TcpStream::connect(&addr)
        .await
        .context("Failed to connect to daemon")?;
    info!("Connected to daemon!");

    let clipboard_packet = Packet::clipboard_text(text.to_string());
    send_packet(&mut stream, &clipboard_packet).await?;
    info!("Sent clipboard text ({} characters)", text.len());

    // Wait for acknowledgment
    let response = receive_packet(&mut stream).await?;
    match response.message {
        Message::Pong => info!("Clipboard text sent successfully!"),
        Message::Error(err) => error!("Daemon returned error: {}", err),
        _ => warn!("Unexpected response: {:?}", response.message),
    }

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
