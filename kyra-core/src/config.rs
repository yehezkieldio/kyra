use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

use crate::{DEFAULT_HOST, DEFAULT_PORT};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    pub network: NetworkConfig,
    pub security: SecurityConfig,
    pub storage: StorageConfig,
    pub logging: LoggingConfig,
    pub discovery: DiscoveryConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub network: NetworkConfig,
    pub security: SecurityConfig,
    pub logging: LoggingConfig,
    pub discovery: DiscoveryConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub host: String,
    pub port: u16,
    pub enable_tls: bool,
    pub cert_file: Option<PathBuf>,
    pub key_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub auth_token: Option<String>,
    pub allowed_hosts: Vec<String>,
    pub require_auth: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub download_dir: PathBuf,
    pub max_file_size: u64,
    pub enable_compression: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub file: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    pub enable_mdns: bool,
    pub service_name: String,
    pub fallback_hosts: Vec<String>,
    pub announce_interval: u64,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            network: NetworkConfig::default(),
            security: SecurityConfig::default(),
            storage: StorageConfig::default(),
            logging: LoggingConfig::default(),
            discovery: DiscoveryConfig::default(),
        }
    }
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            network: NetworkConfig::default(),
            security: SecurityConfig::default(),
            logging: LoggingConfig::default(),
            discovery: DiscoveryConfig::default(),
        }
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            host: DEFAULT_HOST.to_string(),
            port: DEFAULT_PORT,
            enable_tls: false,
            cert_file: None,
            key_file: None,
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            auth_token: None,
            allowed_hosts: vec!["127.0.0.1".to_string(), "::1".to_string()],
            require_auth: false,
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            download_dir: dirs::download_dir()
                .unwrap_or_else(|| dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")))
                .join("kyra"),
            max_file_size: crate::MAX_FILE_SIZE,
            enable_compression: true,
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            file: None,
        }
    }
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            enable_mdns: true,
            service_name: crate::MDNS_SERVICE_NAME.to_string(),
            fallback_hosts: vec!["127.0.0.1".to_string()],
            announce_interval: 30,
        }
    }
}

impl DaemonConfig {
    pub fn load() -> Result<Self> {
        let config_path = Self::config_path()?;

        if config_path.exists() {
            let content = fs::read_to_string(&config_path)?;
            let config: DaemonConfig = toml::from_str(&content)?;
            Ok(config)
        } else {
            let config = Self::default();
            config.save()?;
            Ok(config)
        }
    }

    pub fn save(&self) -> Result<()> {
        let config_path = Self::config_path()?;

        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let content = toml::to_string_pretty(self)?;
        fs::write(&config_path, content)?;
        Ok(())
    }

    fn config_path() -> Result<PathBuf> {
        let config_dir = dirs::config_dir()
            .ok_or_else(|| anyhow::anyhow!("Could not determine config directory"))?;
        Ok(config_dir.join("kyra").join("daemon.toml"))
    }
}

impl AgentConfig {
    pub fn load() -> Result<Self> {
        let config_path = Self::config_path()?;

        if config_path.exists() {
            let content = fs::read_to_string(&config_path)?;
            let config: AgentConfig = toml::from_str(&content)?;
            Ok(config)
        } else {
            let config = Self::default();
            config.save()?;
            Ok(config)
        }
    }

    pub fn save(&self) -> Result<()> {
        let config_path = Self::config_path()?;

        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let content = toml::to_string_pretty(self)?;
        fs::write(&config_path, content)?;
        Ok(())
    }

    fn config_path() -> Result<PathBuf> {
        let config_dir = dirs::config_dir()
            .ok_or_else(|| anyhow::anyhow!("Could not determine config directory"))?;
        Ok(config_dir.join("kyra").join("agent.toml"))
    }
}
