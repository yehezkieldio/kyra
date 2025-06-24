use base64::{Engine as _, engine::general_purpose};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    // Authentication
    Auth {
        token: String,
    },
    AuthSuccess,
    AuthFailure,

    // Discovery
    Ping,
    Pong,

    // File transfer
    FileMetadata {
        name: String,
        size: u64,
        checksum: Option<String>,
        compressed: bool,
    },
    FileChunk {
        data: Vec<u8>,
        sequence: u64,
        total_chunks: u64,
    },
    FileComplete {
        checksum: Option<String>,
    },

    // Clipboard
    ClipboardText(String),
    ClipboardImage {
        format: String,
        data: Vec<u8>,
    },

    // Text message
    TextMessage(String),

    // System
    Error(String),
    Success(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Packet {
    pub id: String,
    pub message: Message,
    pub timestamp: u64,
    pub compressed: bool,
}

impl Packet {
    pub fn new(message: Message) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            message,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            compressed: false,
        }
    }

    pub fn auth(token: String) -> Self {
        Self::new(Message::Auth { token })
    }

    pub fn auth_success() -> Self {
        Self::new(Message::AuthSuccess)
    }

    pub fn auth_failure() -> Self {
        Self::new(Message::AuthFailure)
    }

    pub fn ping() -> Self {
        Self::new(Message::Ping)
    }

    pub fn pong() -> Self {
        Self::new(Message::Pong)
    }

    pub fn file_metadata(
        name: String,
        size: u64,
        checksum: Option<String>,
        compressed: bool,
    ) -> Self {
        Self::new(Message::FileMetadata {
            name,
            size,
            checksum,
            compressed,
        })
    }

    pub fn file_chunk(data: Vec<u8>, sequence: u64, total_chunks: u64) -> Self {
        Self::new(Message::FileChunk {
            data,
            sequence,
            total_chunks,
        })
    }

    pub fn file_complete(checksum: Option<String>) -> Self {
        Self::new(Message::FileComplete { checksum })
    }

    pub fn clipboard_text(text: String) -> Self {
        Self::new(Message::ClipboardText(text))
    }

    pub fn clipboard_image(format: String, data: Vec<u8>) -> Self {
        Self::new(Message::ClipboardImage { format, data })
    }

    pub fn text_message(text: String) -> Self {
        Self::new(Message::TextMessage(text))
    }

    pub fn error(msg: String) -> Self {
        Self::new(Message::Error(msg))
    }

    pub fn success(msg: String) -> Self {
        Self::new(Message::Success(msg))
    }

    pub fn compress(&mut self) -> anyhow::Result<()> {
        if self.compressed {
            return Ok(());
        }

        let serialized = serde_json::to_vec(&self.message)?;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut encoder, &serialized)?;
        let compressed = encoder.finish()?;

        // Only compress if it actually reduces size
        if compressed.len() < serialized.len() {
            // Store compressed data in a special message variant
            self.message = Message::Success(general_purpose::STANDARD.encode(&compressed));
            self.compressed = true;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub last_seen: u64,
    pub capabilities: Vec<String>,
}

impl PeerInfo {
    pub fn new(name: String, host: String, port: u16) -> Self {
        Self {
            name,
            host,
            port,
            last_seen: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            capabilities: vec![
                "file_transfer".to_string(),
                "clipboard_text".to_string(),
                "clipboard_image".to_string(),
                "text_message".to_string(),
            ],
        }
    }
}

pub const DEFAULT_PORT: u16 = 8080;
pub const DEFAULT_HOST: &str = "0.0.0.0";
pub const CHUNK_SIZE: usize = 64 * 1024; // 64 KB
pub const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024 * 1024; // 10 GB
pub const MDNS_SERVICE_TYPE: &str = "_kyra._tcp.local.";
pub const MDNS_SERVICE_NAME: &str = "kyra";

pub fn generate_checksum(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}
