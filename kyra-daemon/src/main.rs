use anyhow::Result;
use arboard::{Clipboard, ImageData};
use kyra_core::{
    DaemonConfig, DiscoveryService, Message, Packet, ensure_dir_exists, format_bytes,
    generate_checksum, is_host_allowed, load_tls_server_config, sanitize_filename,
};
use serde_json;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_rustls::{TlsAcceptor, server::TlsStream};
use tracing::{debug, error, info, warn};
use tracing_subscriber::fmt;

#[derive(Debug)]
struct FileTransfer {
    name: String,
    size: u64,
    received: u64,
    file: File,
    #[allow(dead_code)]
    checksum: Option<String>,
    chunks_received: u64,
    total_chunks: u64,
    start_time: std::time::Instant,
}

#[derive(Debug)]
struct ClientSession {
    #[allow(dead_code)]
    id: String,
    #[allow(dead_code)]
    addr: SocketAddr,
    authenticated: bool,
    file_transfer: Option<FileTransfer>,
}

type ActiveSessions = Arc<Mutex<HashMap<String, ClientSession>>>;

#[tokio::main]
async fn main() -> Result<()> {
    // Load configuration
    let config = DaemonConfig::load()?;

    // Initialize logging
    init_logging(&config)?;

    info!("🚀 Starting Kyra Daemon v0.1.0");

    // Ensure download directory exists
    ensure_dir_exists(&config.storage.download_dir).await?;

    // Start mDNS discovery service if enabled
    let _discovery_service = if config.discovery.enable_mdns {
        match start_discovery_service(&config).await {
            Ok(service) => {
                info!("✅ mDNS discovery service started");
                Some(service)
            }
            Err(e) => {
                warn!("⚠️  Failed to start mDNS discovery: {}", e);
                None
            }
        }
    } else {
        info!("🔍 mDNS discovery disabled");
        None
    };

    // Setup TLS if enabled
    let tls_acceptor = if config.network.enable_tls {
        Some(setup_tls(&config).await?)
    } else {
        None
    };

    let addr = format!("{}:{}", config.network.host, config.network.port);
    let listener = TcpListener::bind(&addr).await?;

    info!("🎯 Daemon listening on {}", addr);
    if config.network.enable_tls {
        info!("🔒 TLS encryption enabled");
    }
    if config.security.require_auth {
        info!("🛡️  Authentication required");
    }

    let active_sessions: ActiveSessions = Arc::new(Mutex::new(HashMap::new()));

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                info!("🔌 New connection from: {}", addr);

                // Check if host is allowed
                if !is_host_allowed(&addr.ip().to_string(), &config.security.allowed_hosts) {
                    warn!("🚫 Rejected connection from unauthorized host: {}", addr);
                    continue;
                }

                let sessions = active_sessions.clone();
                let config = config.clone();
                let tls_acceptor = tls_acceptor.clone();

                tokio::spawn(async move {
                    let session_id = uuid::Uuid::new_v4().to_string();

                    // Insert new session
                    {
                        let mut sessions_guard = sessions.lock().await;
                        sessions_guard.insert(
                            session_id.clone(),
                            ClientSession {
                                id: session_id.clone(),
                                addr,
                                authenticated: !config.security.require_auth,
                                file_transfer: None,
                            },
                        );
                    }

                    let result = if let Some(ref acceptor) = tls_acceptor {
                        match acceptor.accept(stream).await {
                            Ok(tls_stream) => {
                                info!("🔐 TLS handshake completed for {}", addr);
                                handle_connection_tls(tls_stream, session_id, sessions, config)
                                    .await
                            }
                            Err(e) => {
                                error!("❌ TLS handshake failed for {}: {}", addr, e);
                                Err(e.into())
                            }
                        }
                    } else {
                        handle_connection_plain(stream, session_id, sessions, config).await
                    };

                    if let Err(e) = result {
                        error!("❌ Error handling connection from {}: {}", addr, e);
                    }
                });
            }
            Err(e) => {
                error!("❌ Error accepting connection: {}", e);
            }
        }
    }
}

fn init_logging(config: &DaemonConfig) -> Result<()> {
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

async fn handle_connection_plain(
    stream: TcpStream,
    session_id: String,
    sessions: ActiveSessions,
    config: DaemonConfig,
) -> Result<()> {
    let (read_half, write_half) = stream.into_split();
    handle_connection_impl(read_half, write_half, session_id, sessions, config).await
}

async fn handle_connection_tls(
    stream: TlsStream<TcpStream>,
    session_id: String,
    sessions: ActiveSessions,
    config: DaemonConfig,
) -> Result<()> {
    let (read_half, write_half) = tokio::io::split(stream);
    handle_connection_impl(read_half, write_half, session_id, sessions, config).await
}

async fn handle_connection_impl<R, W>(
    read_half: R,
    mut write_half: W,
    session_id: String,
    sessions: ActiveSessions,
    config: DaemonConfig,
) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut reader = TokioBufReader::new(read_half);
    let mut line = String::new();

    info!("📡 Client session started: {}", session_id);

    loop {
        line.clear();
        match reader.read_line(&mut line).await? {
            0 => {
                info!("👋 Client disconnected: {}", session_id);
                break;
            }
            _ => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }

                debug!("📨 Raw message: {}", trimmed);

                match serde_json::from_str::<Packet>(trimmed) {
                    Ok(packet) => {
                        debug!("📦 Received packet: {:?}", packet.message);

                        let response =
                            handle_message(packet, &session_id, &sessions, &config).await;

                        match response {
                            Ok(Some(response_packet)) => {
                                let response_json = serde_json::to_string(&response_packet)?;
                                write_half.write_all(response_json.as_bytes()).await?;
                                write_half.write_all(b"\n").await?;
                                write_half.flush().await?;
                            }
                            Ok(None) => {
                                // No response needed
                            }
                            Err(e) => {
                                error!("❌ Error handling message: {}", e);
                                let error_packet = Packet::error(format!("Error: {}", e));
                                let error_json = serde_json::to_string(&error_packet)?;
                                write_half.write_all(error_json.as_bytes()).await?;
                                write_half.write_all(b"\n").await?;
                                write_half.flush().await?;
                            }
                        }
                    }
                    Err(e) => {
                        error!("❌ Failed to deserialize message: {}", e);
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

    // Clean up session
    {
        let mut sessions_guard = sessions.lock().await;
        sessions_guard.remove(&session_id);
    }

    Ok(())
}

async fn handle_message(
    packet: Packet,
    session_id: &str,
    sessions: &ActiveSessions,
    config: &DaemonConfig,
) -> Result<Option<Packet>> {
    let mut sessions_guard = sessions.lock().await;
    let session = sessions_guard
        .get_mut(session_id)
        .ok_or_else(|| anyhow::anyhow!("Session not found"))?;

    match packet.message {
        Message::Auth { token } => {
            if let Some(expected_token) = &config.security.auth_token {
                if kyra_core::verify_auth_token(&token, expected_token) {
                    session.authenticated = true;
                    info!("✅ Authentication successful for session {}", session_id);
                    Ok(Some(Packet::auth_success()))
                } else {
                    warn!("🚫 Authentication failed for session {}", session_id);
                    Ok(Some(Packet::auth_failure()))
                }
            } else {
                // No auth token configured, accept any auth attempt
                session.authenticated = true;
                Ok(Some(Packet::auth_success()))
            }
        }
        _ if config.security.require_auth && !session.authenticated => {
            warn!("🚫 Unauthenticated request from session {}", session_id);
            Ok(Some(Packet::error("Authentication required".to_string())))
        }
        Message::Ping => {
            debug!("🏓 Ping from session {}", session_id);
            Ok(Some(Packet::pong()))
        }
        Message::Pong => {
            debug!("🏓 Pong from session {}", session_id);
            Ok(None)
        }
        Message::FileMetadata {
            name,
            size,
            checksum,
            compressed: _,
        } => {
            if size > config.storage.max_file_size {
                return Ok(Some(Packet::error(format!(
                    "File too large: {} > {}",
                    format_bytes(size),
                    format_bytes(config.storage.max_file_size)
                ))));
            }

            let sanitized_name = sanitize_filename(&name);
            let file_path = config.storage.download_dir.join(&sanitized_name);

            info!(
                "📁 Starting file transfer: {} ({}) -> {}",
                name,
                format_bytes(size),
                file_path.display()
            );

            let file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&file_path)?;

            let transfer = FileTransfer {
                name: sanitized_name,
                size,
                received: 0,
                file,
                checksum,
                chunks_received: 0,
                total_chunks: 0,
                start_time: std::time::Instant::now(),
            };

            session.file_transfer = Some(transfer);
            Ok(Some(Packet::success("Ready to receive file".to_string())))
        }
        Message::FileChunk {
            data,
            sequence,
            total_chunks,
        } => {
            if let Some(transfer) = &mut session.file_transfer {
                transfer.file.write_all(&data)?;
                transfer.file.flush()?;
                transfer.received += data.len() as u64;
                transfer.chunks_received += 1;
                transfer.total_chunks = total_chunks;

                let progress = (transfer.received as f64 / transfer.size as f64) * 100.0;
                let elapsed = transfer.start_time.elapsed();
                let speed = transfer.received as f64 / elapsed.as_secs_f64();

                debug!(
                    "📊 File chunk {}/{}: {} / {} ({:.1}%) at {}/s",
                    sequence,
                    total_chunks,
                    format_bytes(transfer.received),
                    format_bytes(transfer.size),
                    progress,
                    format_bytes(speed as u64)
                );

                Ok(None)
            } else {
                Err(anyhow::anyhow!("No active file transfer"))
            }
        }
        Message::FileComplete { checksum } => {
            if let Some(transfer) = session.file_transfer.take() {
                drop(transfer.file);

                let elapsed = transfer.start_time.elapsed();
                let speed = transfer.received as f64 / elapsed.as_secs_f64();

                if transfer.received == transfer.size {
                    info!(
                        "✅ File transfer completed: {} ({}) in {:.1}s at {}/s",
                        transfer.name,
                        format_bytes(transfer.received),
                        elapsed.as_secs_f64(),
                        format_bytes(speed as u64)
                    );

                    // Verify checksum if provided
                    if let Some(expected_checksum) = checksum {
                        let file_path = config.storage.download_dir.join(&transfer.name);
                        let file_data = std::fs::read(&file_path)?;
                        let actual_checksum = generate_checksum(&file_data);

                        if actual_checksum != expected_checksum {
                            warn!(
                                "⚠️  Checksum mismatch for {}: expected {}, got {}",
                                transfer.name, expected_checksum, actual_checksum
                            );
                            return Ok(Some(Packet::error(
                                "Checksum verification failed".to_string(),
                            )));
                        }

                        info!("✅ Checksum verified for {}", transfer.name);
                    }

                    // Send notification
                    if let Err(e) =
                        notifica::notify("Kyra", &format!("File received: {}", transfer.name))
                    {
                        warn!("⚠️  Failed to send notification: {}", e);
                    }

                    Ok(Some(Packet::success(
                        "File received successfully".to_string(),
                    )))
                } else {
                    warn!(
                        "⚠️  File size mismatch: expected {}, received {}",
                        transfer.size, transfer.received
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
            info!("📋 Clipboard text received: {} characters", text.len());

            match Clipboard::new() {
                Ok(mut clipboard) => {
                    if let Err(e) = clipboard.set_text(text) {
                        error!("❌ Failed to set clipboard text: {}", e);
                        return Ok(Some(Packet::error(format!(
                            "Failed to set clipboard: {}",
                            e
                        ))));
                    }

                    info!("✅ Clipboard text updated");

                    if let Err(e) = notifica::notify("Kyra", "Clipboard text updated!") {
                        warn!("⚠️  Failed to send notification: {}", e);
                    }

                    Ok(Some(Packet::success("Clipboard text updated".to_string())))
                }
                Err(e) => {
                    error!("❌ Failed to access clipboard: {}", e);
                    Ok(Some(Packet::error(format!(
                        "Failed to access clipboard: {}",
                        e
                    ))))
                }
            }
        }
        Message::ClipboardImage { format, data } => {
            info!(
                "🖼️  Clipboard image received: {} format, {} bytes",
                format,
                data.len()
            );

            match Clipboard::new() {
                Ok(mut clipboard) => {
                    let image_data = ImageData {
                        width: 0, // Will be determined by arboard
                        height: 0,
                        bytes: data.into(),
                    };

                    if let Err(e) = clipboard.set_image(image_data) {
                        error!("❌ Failed to set clipboard image: {}", e);
                        return Ok(Some(Packet::error(format!(
                            "Failed to set clipboard image: {}",
                            e
                        ))));
                    }

                    info!("✅ Clipboard image updated");

                    if let Err(e) = notifica::notify("Kyra", "Clipboard image updated!") {
                        warn!("⚠️  Failed to send notification: {}", e);
                    }

                    Ok(Some(Packet::success("Clipboard image updated".to_string())))
                }
                Err(e) => {
                    error!("❌ Failed to access clipboard: {}", e);
                    Ok(Some(Packet::error(format!(
                        "Failed to access clipboard: {}",
                        e
                    ))))
                }
            }
        }
        Message::TextMessage(text) => {
            info!("💬 Text message received: {}", text);

            if let Err(e) = notifica::notify("Kyra Message", &text) {
                warn!("⚠️  Failed to send notification: {}", e);
            }

            Ok(Some(Packet::success("Message received".to_string())))
        }
        Message::Error(ref err) => {
            warn!("❌ Error received: {}", err);
            Ok(None)
        }
        _ => {
            warn!("❓ Unknown message type received");
            Ok(Some(Packet::error("Unknown message type".to_string())))
        }
    }
}

async fn start_discovery_service(config: &DaemonConfig) -> Result<DiscoveryService> {
    let service = DiscoveryService::new(config.discovery.service_name.clone())?;

    let hostname = hostname::get()
        .unwrap_or_else(|_| "kyra-daemon".into())
        .to_string_lossy()
        .to_string();

    service
        .start_advertising(config.network.port, &hostname)
        .await?;
    Ok(service)
}

async fn setup_tls(config: &DaemonConfig) -> Result<TlsAcceptor> {
    let cert_path = config
        .network
        .cert_file
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("TLS enabled but no cert file specified"))?;
    let key_path = config
        .network
        .key_file
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("TLS enabled but no key file specified"))?;

    if !cert_path.exists() || !key_path.exists() {
        info!("🔑 Generating self-signed certificate...");
        let hostname = hostname::get()
            .unwrap_or_else(|_| "localhost".into())
            .to_string_lossy()
            .to_string();

        // Ensure cert directory exists
        if let Some(parent) = cert_path.parent() {
            ensure_dir_exists(parent).await?;
        }

        kyra_core::generate_self_signed_cert(cert_path, key_path, &hostname)?;
        info!("✅ Self-signed certificate generated");
    }

    let server_config = load_tls_server_config(cert_path, key_path)?;
    Ok(TlsAcceptor::from(server_config))
}
