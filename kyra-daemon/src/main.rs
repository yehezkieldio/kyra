use anyhow::Result;
use kyra_core::{DEFAULT_HOST, DEFAULT_PORT, Message, Packet};
use serde_json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};
use tokio::net::{TcpListener as TokioTcpListener, TcpStream as TokioTcpStream};

#[tokio::main]
async fn main() -> Result<()> {
    println!("Starting Kyra Daemon...");

    let addr = format!("{}:{}", DEFAULT_HOST, DEFAULT_PORT);
    let listener = TokioTcpListener::bind(&addr).await?;

    println!("Daemon listening on {}", addr);

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                println!("New connection from: {}", addr);
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream).await {
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

async fn handle_connection(stream: TokioTcpStream) -> Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = TokioBufReader::new(read_half);
    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line).await? {
            0 => {
                println!("Client disconnected");
                break;
            }
            _ => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }

                match serde_json::from_str::<Packet>(trimmed) {
                    Ok(packet) => {
                        println!("Received packet: {:?}", packet);

                        let response = match packet.message {
                            Message::Ping => {
                                println!("Received Ping, sending Pong");
                                Packet::pong()
                            }
                            Message::Pong => {
                                println!("Received Pong");
                                continue;
                            }
                            Message::Error(ref err) => {
                                println!("Received Error: {}", err);
                                continue;
                            }
                            Message::FileMetadata { name, size } => {
                                println!("Received FileMetadata: name={}, size={}", name, size);
                                Packet::file_metadata(name, size)
                            }
                            Message::FileChunk(data) => {
                                println!("Received FileChunk of size: {}", data.len());
                                Packet::file_chunk(data)
                            }
                            Message::FileComplete => {
                                println!("Received FileComplete");
                                Packet::file_complete()
                            }
                            Message::ClipboardText(text) => {
                                println!("Received ClipboardText: {}", text);
                                Packet::clipboard_text(text)
                            }
                        };

                        let response_json = serde_json::to_string(&response)?;
                        write_half.write_all(response_json.as_bytes()).await?;
                        write_half.write_all(b"\n").await?;
                        write_half.flush().await?;
                    }
                    Err(e) => {
                        eprintln!("Failed to deserialize message: {}", e);
                        let error_packet = Packet::error(format!("Invalid message format: {}", e));
                        let error_json = serde_json::to_string(&error_packet)?;
                        write_half.write_all(error_json.as_bytes()).await?;
                        write_half.write_all(b"\n").await?;
                        write_half.flush().await?;
                    }
                }
            }
        }
    }

    Ok(())
}
