use anyhow::Result;
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;
use tracing::{debug, info};

use crate::{MDNS_SERVICE_NAME, MDNS_SERVICE_TYPE, PeerInfo};

pub struct DiscoveryService {
    daemon: ServiceDaemon,
    peers: HashMap<String, PeerInfo>,
    service_name: String,
}

impl DiscoveryService {
    pub fn new(service_name: String) -> Result<Self> {
        let daemon = ServiceDaemon::new()?;
        Ok(Self {
            daemon,
            peers: HashMap::new(),
            service_name,
        })
    }

    pub async fn start_advertising(&self, port: u16, hostname: &str) -> Result<()> {
        let my_service = ServiceInfo::new(
            MDNS_SERVICE_TYPE,
            &self.service_name,
            hostname,
            IpAddr::V4("0.0.0.0".parse().unwrap()),
            port,
            None,
        )?;

        self.daemon
            .register(my_service)
            .map_err(|e| anyhow::anyhow!("Failed to register mDNS service: {}", e))?;

        info!("Started advertising Kyra service on port {}", port);
        Ok(())
    }

    pub async fn discover_peers(&mut self, timeout: Duration) -> Result<Vec<PeerInfo>> {
        let receiver = self
            .daemon
            .browse(MDNS_SERVICE_TYPE)
            .map_err(|e| anyhow::anyhow!("Failed to start mDNS browsing: {}", e))?;

        let mut discovered = Vec::new();
        let start_time = std::time::Instant::now();

        while start_time.elapsed() < timeout {
            match receiver.recv_timeout(Duration::from_millis(100)) {
                Ok(event) => match event {
                    ServiceEvent::ServiceResolved(info) => {
                        debug!("Discovered service: {:?}", info);

                        if let Some(peer_info) = self.service_info_to_peer(&info) {
                            if peer_info.name != self.service_name {
                                info!(
                                    "Discovered peer: {} at {}:{}",
                                    peer_info.name, peer_info.host, peer_info.port
                                );

                                self.peers.insert(peer_info.name.clone(), peer_info.clone());
                                discovered.push(peer_info);
                            }
                        }
                    }
                    ServiceEvent::ServiceRemoved(typ, name) => {
                        debug!("Service removed: {} {}", typ, name);
                        self.peers.remove(&name);
                    }
                    _ => {}
                },
                Err(_) => {
                    // Timeout, continue loop
                }
            }
        }

        Ok(discovered)
    }

    pub fn get_peers(&self) -> Vec<PeerInfo> {
        self.peers.values().cloned().collect()
    }

    pub fn get_peer(&self, name: &str) -> Option<&PeerInfo> {
        self.peers.get(name)
    }

    fn service_info_to_peer(&self, info: &ServiceInfo) -> Option<PeerInfo> {
        let addresses = info.get_addresses();
        if let Some(addr) = addresses.iter().next() {
            Some(PeerInfo::new(
                info.get_fullname()
                    .replace(&format!(".{}", MDNS_SERVICE_TYPE), ""),
                addr.to_string(),
                info.get_port(),
            ))
        } else {
            None
        }
    }

    pub fn stop(&self) -> Result<()> {
        self.daemon
            .shutdown()
            .map_err(|e| anyhow::anyhow!("Failed to shutdown mDNS daemon: {}", e))?;
        Ok(())
    }
}

impl Drop for DiscoveryService {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

pub async fn discover_peers_simple(timeout: Duration) -> Result<Vec<PeerInfo>> {
    let mut service = DiscoveryService::new(format!("{}-temp", MDNS_SERVICE_NAME))?;
    service.discover_peers(timeout).await
}
