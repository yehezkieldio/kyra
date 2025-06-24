use anyhow::Result;
use std::path::Path;
use tokio::fs;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::info;

pub async fn copy_with_progress<R, W>(
    mut reader: R,
    mut writer: W,
    total_size: u64,
    progress_callback: impl Fn(u64, u64),
) -> Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buffer = vec![0u8; crate::CHUNK_SIZE];
    let mut bytes_copied = 0u64;

    loop {
        let bytes_read = reader.read(&mut buffer).await?;
        if bytes_read == 0 {
            break;
        }

        writer.write_all(&buffer[..bytes_read]).await?;
        bytes_copied += bytes_read as u64;

        progress_callback(bytes_copied, total_size);
    }

    writer.flush().await?;
    Ok(bytes_copied)
}

pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_index = 0;

    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    if unit_index == 0 {
        format!("{} {}", size as u64, UNITS[unit_index])
    } else {
        format!("{:.1} {}", size, UNITS[unit_index])
    }
}

pub fn format_duration(seconds: u64) -> String {
    let hours = seconds / 3600;
    let minutes = (seconds % 3600) / 60;
    let secs = seconds % 60;

    if hours > 0 {
        format!("{:02}:{:02}:{:02}", hours, minutes, secs)
    } else {
        format!("{:02}:{:02}", minutes, secs)
    }
}

pub async fn ensure_dir_exists(path: &Path) -> Result<()> {
    if !path.exists() {
        fs::create_dir_all(path).await?;
        info!("Created directory: {}", path.display());
    }
    Ok(())
}

pub fn sanitize_filename(filename: &str) -> String {
    let invalid_chars = ['<', '>', ':', '"', '/', '\\', '|', '?', '*'];
    let mut sanitized = String::new();

    for ch in filename.chars() {
        if invalid_chars.contains(&ch) || ch.is_control() {
            sanitized.push('_');
        } else {
            sanitized.push(ch);
        }
    }

    // Remove leading/trailing whitespace and dots
    sanitized.trim_matches(|c: char| c.is_whitespace() || c == '.').to_string()
}

pub fn get_file_extension(filename: &str) -> Option<&str> {
    Path::new(filename)
        .extension()
        .and_then(|ext| ext.to_str())
}

pub fn is_image_file(filename: &str) -> bool {
    if let Some(ext) = get_file_extension(filename) {
        matches!(ext.to_lowercase().as_str(), "jpg" | "jpeg" | "png" | "gif" | "bmp" | "webp" | "tiff")
    } else {
        false
    }
}

pub fn calculate_transfer_speed(bytes: u64, elapsed_seconds: f64) -> f64 {
    if elapsed_seconds > 0.0 {
        bytes as f64 / elapsed_seconds
    } else {
        0.0
    }
}

pub fn estimate_time_remaining(bytes_remaining: u64, current_speed: f64) -> Option<u64> {
    if current_speed > 0.0 {
        Some((bytes_remaining as f64 / current_speed) as u64)
    } else {
        None
    }
}
