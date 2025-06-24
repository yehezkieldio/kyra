use anyhow::{Context, Result};
use clap::{Arg, Command};
use kyra_core::{CHUNK_SIZE, DEFAULT_HOST, DEFAULT_PORT, Message, Packet};
use serde_json;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> Result<()> {
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
            send_ping().await?;
        }
        Some(("send", send_matches)) => match send_matches.subcommand() {
            Some(("file", file_matches)) => {
                let file_path = file_matches.get_one::<String>("path").unwrap();
                send_file(file_path).await?;
            }
            Some(("clipboard", clipboard_matches)) => {
                let text = clipboard_matches.get_one::<String>("text").unwrap();
                send_clipboard_text(text).await?;
            }
            _ => {
                eprintln!("Unknown send command. Use 'file' or 'clipboard'");
            }
        },
        _ => {
            eprintln!("No command specified. Use 'ping' or 'send'");
        }
    }

    Ok(())
}

async fn send_ping() -> Result<()> {
    println!("Starting Kyra Agent - Ping...");

    let addr = format!("{}:{}", DEFAULT_HOST, DEFAULT_PORT);
    println!("Connecting to daemon at {}", addr);

    let mut stream = TcpStream::connect(&addr)
        .await
        .context("Failed to connect to daemon")?;
    println!("Connected to daemon!");

    // Send ping
    let ping_packet = Packet::ping();
    send_packet(&mut stream, &ping_packet).await?;
    println!("Sent ping: {:?}", ping_packet);

    // Wait for response
    let response = receive_packet(&mut stream).await?;
    match response.message {
        Message::Pong => println!("Successfully received Pong!"),
        Message::Error(err) => println!("Daemon returned error: {}", err),
        _ => println!("Unexpected response: {:?}", response.message),
    }

    Ok(())
}

async fn send_file(file_path: &str) -> Result<()> {
    println!("Starting Kyra Agent - File Transfer...");

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

    println!("Sending file: {} ({} bytes)", file_name, file_size);

    let addr = format!("{}:{}", DEFAULT_HOST, DEFAULT_PORT);
    let mut stream = TcpStream::connect(&addr)
        .await
        .context("Failed to connect to daemon")?;
    println!("Connected to daemon!");

    // Send file metadata
    let metadata_packet = Packet::file_metadata(file_name.clone(), file_size);
    send_packet(&mut stream, &metadata_packet).await?;
    println!("Sent file metadata: {} ({} bytes)", file_name, file_size);

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
        send_packet(&mut stream, &chunk_packet).await?;

        bytes_sent += bytes_read as u64;
        println!(
            "Sent chunk: {} / {} bytes ({:.1}%)",
            bytes_sent,
            file_size,
            (bytes_sent as f64 / file_size as f64) * 100.0
        );
    }

    // Send completion signal
    let complete_packet = Packet::file_complete();
    send_packet(&mut stream, &complete_packet).await?;
    println!("File transfer completed!");

    Ok(())
}

async fn send_clipboard_text(text: &str) -> Result<()> {
    println!("Starting Kyra Agent - Clipboard Transfer...");

    let addr = format!("{}:{}", DEFAULT_HOST, DEFAULT_PORT);
    let mut stream = TcpStream::connect(&addr)
        .await
        .context("Failed to connect to daemon")?;
    println!("Connected to daemon!");

    let clipboard_packet = Packet::clipboard_text(text.to_string());
    send_packet(&mut stream, &clipboard_packet).await?;
    println!("Sent clipboard text ({} characters)", text.len());

    // Wait for acknowledgment
    let response = receive_packet(&mut stream).await?;
    match response.message {
        Message::Pong => println!("Clipboard text sent successfully!"),
        Message::Error(err) => println!("Daemon returned error: {}", err),
        _ => println!("Unexpected response: {:?}", response.message),
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
