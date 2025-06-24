use anyhow::Result;
use kyra_core::{DEFAULT_HOST, DEFAULT_PORT, Message, Packet};
use serde_json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> Result<()> {
    println!("Starting Kyra Agent...");

    let addr = format!("{}:{}", DEFAULT_HOST, DEFAULT_PORT);
    println!("Connecting to daemon at {}", addr);

    let mut stream = TcpStream::connect(&addr).await?;
    println!("Connected to daemon!");

    // Send a ping message
    let ping_packet = Packet::ping();
    let ping_json = serde_json::to_string(&ping_packet)?;

    println!("Sending ping: {:?}", ping_packet);
    stream.write_all(ping_json.as_bytes()).await?;
    stream.write_all(b"\n").await?;
    stream.flush().await?;

    // Wait for response
    let mut reader = BufReader::new(&mut stream);
    let mut response = String::new();

    match reader.read_line(&mut response).await? {
        0 => {
            println!("Connection closed by daemon");
        }
        _ => {
            let trimmed = response.trim();
            match serde_json::from_str::<Packet>(trimmed) {
                Ok(packet) => {
                    println!("Received response: {:?}", packet);
                    match packet.message {
                        Message::Pong => println!("Successfully received Pong!"),
                        Message::Error(err) => println!("Daemon returned error: {}", err),
                        _ => println!("Unexpected response: {:?}", packet.message),
                    }
                }
                Err(e) => {
                    eprintln!("Failed to deserialize response: {}", e);
                }
            }
        }
    }

    Ok(())
}
