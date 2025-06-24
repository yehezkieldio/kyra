use anyhow::Result;
use rustls::{ServerConfig, ClientConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use base64::{Engine as _, engine::general_purpose};

pub fn generate_auth_token(passphrase: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(passphrase.as_bytes());
    hasher.update(b"kyra-salt-2024");
    general_purpose::STANDARD.encode(hasher.finalize())
}

pub fn verify_auth_token(token: &str, expected_token: &str) -> bool {
    token == expected_token
}

pub fn load_tls_server_config(cert_path: &Path, key_path: &Path) -> Result<Arc<ServerConfig>> {
    let cert_file = File::open(cert_path)?;
    let mut cert_reader = BufReader::new(cert_file);
    let cert_chain: Vec<_> = certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()?;

    let key_file = File::open(key_path)?;
    let mut key_reader = BufReader::new(key_file);
    let mut keys: Vec<_> = pkcs8_private_keys(&mut key_reader)
        .collect::<Result<Vec<_>, _>>()?;

    if keys.is_empty() {
        return Err(anyhow::anyhow!("No private keys found in key file"));
    }

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, keys.remove(0).into())?;

    Ok(Arc::new(config))
}

pub fn load_tls_client_config() -> Result<Arc<ClientConfig>> {
    let config = ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();

    Ok(Arc::new(config))
}

pub fn generate_self_signed_cert(
    cert_path: &Path,
    key_path: &Path,
    hostname: &str,
) -> Result<()> {
    use std::process::Command;

    // Generate self-signed certificate using openssl
    let output = Command::new("openssl")
        .args(&[
            "req", "-x509", "-newkey", "rsa:4096", "-keyout",
            key_path.to_str().unwrap(),
            "-out", cert_path.to_str().unwrap(),
            "-days", "365", "-nodes",
            "-subj", &format!("/CN={}", hostname),
        ])
        .output()?;

    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "Failed to generate certificate: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    Ok(())
}

pub fn is_host_allowed(host: &str, allowed_hosts: &[String]) -> bool {
    if allowed_hosts.is_empty() {
        return true;
    }

    allowed_hosts.iter().any(|allowed| {
        allowed == host ||
        allowed == "*" ||
        (allowed.starts_with("*.") && host.ends_with(&allowed[1..]))
    })
}
