use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    Ping,
    Pong,
    FileMetadata { name: String, size: u64 },
    FileChunk(Vec<u8>),
    ClipboardText(String),
    FileComplete,
    Error(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Packet {
    pub message: Message,
    pub timestamp: u64,
}

impl Packet {
    pub fn new(message: Message) -> Self {
        Self {
            message,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    pub fn ping() -> Self {
        Self::new(Message::Ping)
    }

    pub fn pong() -> Self {
        Self::new(Message::Pong)
    }

    pub fn file_metadata(name: String, size: u64) -> Self {
        Self::new(Message::FileMetadata { name, size })
    }

    pub fn file_chunk(data: Vec<u8>) -> Self {
        Self::new(Message::FileChunk(data))
    }

    pub fn file_complete() -> Self {
        Self::new(Message::FileComplete)
    }

    pub fn clipboard_text(text: String) -> Self {
        Self::new(Message::ClipboardText(text))
    }

    pub fn error(msg: String) -> Self {
        Self::new(Message::Error(msg))
    }
}

pub const DEFAULT_PORT: u16 = 8080;
pub const DEFAULT_HOST: &str = "127.0.0.1";
pub const CHUNK_SIZE: usize = 64 * 1024; // 64 KB
