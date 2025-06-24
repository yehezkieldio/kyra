use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    Ping,
    Pong,
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

    pub fn error(msg: String) -> Self {
        Self::new(Message::Error(msg))
    }
}

pub const DEFAULT_PORT: u16 = 8080;
pub const DEFAULT_HOST: &str = "127.0.0.1";
