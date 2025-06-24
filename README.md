# Kyra - Secure Cross-Platform Data Transfer

**Kyra** is a lightweight, secure, cross-platform system for seamless transfer of files, text, images, and clipboard content between devices over a local network. Built in **Rust**, Kyra prioritizes performance, simplicity, and daily productivity.

## 🚀 Features

### 🔹 **Transfer Types**
- **📁 Files**: Transfer files of any type with integrity verification
- **📋 Clipboard**: Sync text and images between clipboards
- **💬 Text Messages**: Send quick text notifications
- **🖼️ Images**: Direct image clipboard sharing

### 🔹 **Security**
- **🔐 TLS Encryption**: Optional TLS 1.3 encryption for all communications
- **🛡️ Authentication**: Token-based authentication with SHA-256 hashing
- **🌐 Network Controls**: IP allowlisting and host restrictions
- **✅ Integrity**: File checksum verification

### 🔹 **Discovery**
- **🔍 mDNS Auto-Discovery**: Automatically find peers on local network
- **📋 Fallback Hosts**: Manual host configuration as backup
- **🎯 Smart Targeting**: Automatic peer selection or manual override

### 🔹 **Cross-Platform**
- **🐧 Linux**: Full support with systemd integration
- **🪟 Windows**: Windows Service support
- **🔄 Seamless**: Same commands and features across platforms

---

## 📦 Installation

### Building from Source

```bash
# Clone the repository
git clone <repository-url>
cd kyra

# Build all components
cargo build --release

# Install binaries (optional)
cargo install --path kyra-daemon
cargo install --path kyra-agent
```

### Binary Installation

Download pre-built binaries from the releases page for your platform.

---

## ⚙️ Configuration

Kyra uses TOML configuration files stored in:
- **Linux**: `~/.config/kyra/`
- **Windows**: `%APPDATA%/kyra/`

### Daemon Configuration (`daemon.toml`)

```toml
[network]
host = "0.0.0.0"
port = 8080
enable_tls = false
# cert_file = "/path/to/cert.pem"  # Required if TLS enabled
# key_file = "/path/to/key.pem"   # Required if TLS enabled

[security]
require_auth = false
# auth_token = "your-generated-token"  # Generate with: kyra-agent auth generate-token
allowed_hosts = ["127.0.0.1", "::1", "192.168.1.0/24"]

[storage]
download_dir = "~/Downloads/kyra"
max_file_size = 10737418240  # 10GB
enable_compression = true

[logging]
level = "info"
# file = "/var/log/kyra/daemon.log"  # Optional log file

[discovery]
enable_mdns = true
service_name = "kyra-daemon"
fallback_hosts = ["192.168.1.100:8080"]
announce_interval = 30
```

### Agent Configuration (`agent.toml`)

```toml
[network]
host = "127.0.0.1"  # Default target
port = 8080
enable_tls = false

[security]
require_auth = false
# auth_token = "your-generated-token"
allowed_hosts = []

[logging]
level = "info"

[discovery]
enable_mdns = true
service_name = "kyra-agent"
fallback_hosts = ["192.168.1.100:8080", "192.168.1.101:8080"]
announce_interval = 30
```

---

## 🎯 Usage

### Starting the Daemon

```bash
# Run daemon in foreground
kyra-daemon

# Or as systemd service (Linux)
sudo systemctl enable kyra-daemon
sudo systemctl start kyra-daemon
```

### Using the Agent

#### Discovery
```bash
# Find peers on network
kyra-agent discover
```

#### File Transfer
```bash
# Send a file (auto-discover target)
kyra-agent send file /path/to/document.pdf

# Send to specific host
kyra-agent send file /path/to/image.jpg --host 192.168.1.100:8080
```

#### Clipboard Operations
```bash
# Send current clipboard content (text or image)
kyra-agent send clipboard

# Send to specific host
kyra-agent send clipboard --host 192.168.1.100:8080
```

#### Text Messages
```bash
# Send a text notification
kyra-agent send text "Build completed successfully!"

# Send to specific host
kyra-agent send text "Meeting in 5 minutes" --host 192.168.1.100:8080
```

#### Testing Connectivity
```bash
# Ping auto-discovered peer
kyra-agent ping

# Ping specific host
kyra-agent ping --host 192.168.1.100:8080
```

---

## 🔐 Security Setup

### 1. Generate Authentication Token
```bash
kyra-agent auth generate-token "your-secure-passphrase"
```

### 2. Update Daemon Configuration
Add the generated token to `daemon.toml`:
```toml
[security]
require_auth = true
auth_token = "generated-token-here"
```

### 3. Update Agent Configuration
Add the same token to `agent.toml`:
```toml
[security]
require_auth = true
auth_token = "same-token-here"
```

### 4. Enable TLS (Optional)
```toml
[network]
enable_tls = true
cert_file = "/path/to/cert.pem"
key_file = "/path/to/key.pem"
```

Kyra will auto-generate self-signed certificates if files don't exist.

---

## 🐧 Linux Systemd Service

### Daemon Service (`/etc/systemd/system/kyra-daemon.service`)

```ini
[Unit]
Description=Kyra Daemon - Secure Data Transfer Service
After=network.target

[Service]
Type=simple
User=kyra
Group=kyra
ExecStart=/usr/local/bin/kyra-daemon
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security settings
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/home/kyra/.config/kyra /home/kyra/Downloads
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

### Setup Commands
```bash
# Create kyra user
sudo useradd -r -s /bin/false kyra

# Create directories
sudo mkdir -p /home/kyra/.config/kyra
sudo mkdir -p /home/kyra/Downloads/kyra
sudo chown -R kyra:kyra /home/kyra

# Install service
sudo systemctl daemon-reload
sudo systemctl enable kyra-daemon
sudo systemctl start kyra-daemon
```

---

## 🪟 Windows Service

Kyra can run as a Windows Service using tools like `nssm` or `winsw`.

### Using NSSM
```cmd
# Install NSSM and register service
nssm install KyraDaemon "C:\Program Files\Kyra\kyra-daemon.exe"
nssm set KyraDaemon DisplayName "Kyra Data Transfer Daemon"
nssm set KyraDaemon Description "Secure cross-platform data transfer service"
nssm start KyraDaemon
```

---

## 🔧 Troubleshooting

### Connection Issues
```bash
# Check if daemon is running
kyra-agent ping

# Check network discovery
kyra-agent discover

# Test specific host
kyra-agent ping --host IP:PORT
```

### File Transfer Issues
- Verify file permissions and disk space
- Check `max_file_size` setting
- Review daemon logs for errors

### mDNS Discovery Issues
- Ensure mDNS/Bonjour is installed
- Check firewall settings for UDP 5353
- Verify `enable_mdns = true` in config

### Authentication Issues
- Verify tokens match between daemon and agent
- Check `require_auth` settings
- Generate new token if needed

---

## 📊 Architecture

```
┌─────────────────┐         ┌─────────────────┐
│   Laptop 1      │         │   Laptop 2      │
│                 │         │                 │
│ ┌─────────────┐ │         │ ┌─────────────┐ │
│ │kyra-daemon  │ │◄────────┤ │kyra-agent   │ │
│ │(server)     │ │  TLS/TCP │ │(client)     │ │
│ └─────────────┘ │         │ └─────────────┘ │
│        │        │         │        │        │
│ ┌─────────────┐ │         │ ┌─────────────┐ │
│ │ Clipboard   │ │         │ │ Clipboard   │ │
│ │ Files       │ │         │ │ Files       │ │
│ │ Notifications│ │         │ │ UI/CLI      │ │
│ └─────────────┘ │         │ └─────────────┘ │
└─────────────────┘         └─────────────────┘
         ▲                           │
         │        mDNS Discovery     │
         └───────────────────────────┘
```

### Components
- **kyra-daemon**: Background service handling incoming requests
- **kyra-agent**: CLI client for initiating transfers
- **kyra-core**: Shared protocol, configuration, and utilities

---

## 🛠️ Development

### Project Structure
```
kyra/
├── kyra-core/          # Shared library
│   ├── src/
│   │   ├── lib.rs
│   │   ├── protocol.rs # Message definitions
│   │   ├── config.rs   # Configuration handling
│   │   ├── discovery.rs# mDNS implementation
│   │   ├── security.rs # TLS and auth
│   │   └── utils.rs    # Helper functions
├── kyra-daemon/        # Server component
│   └── src/main.rs
├── kyra-agent/         # Client component
│   └── src/main.rs
└── Cargo.toml          # Workspace definition
```

### Building
```bash
# Debug build
cargo build

# Release build
cargo build --release

# Run tests
cargo test

# Run with logging
RUST_LOG=debug cargo run --bin kyra-daemon
```

---

## 📋 Protocol Specification

Kyra uses a JSON-based protocol over TCP with optional TLS encryption.

### Message Format
```json
{
  "id": "uuid-v4",
  "message": { /* Message payload */ },
  "timestamp": 1640995200,
  "compressed": false
}
```

### Message Types
- `Auth { token }` - Authentication request
- `Ping` / `Pong` - Connectivity test
- `FileMetadata { name, size, checksum, compressed }` - File transfer start
- `FileChunk { data, sequence, total_chunks }` - File data chunk
- `FileComplete { checksum }` - File transfer completion
- `ClipboardText(String)` - Text clipboard content
- `ClipboardImage { format, data }` - Image clipboard content
- `TextMessage(String)` - Text notification
- `Error(String)` / `Success(String)` - Status responses

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

### Code Style
- Run `cargo fmt` before committing
- Follow Rust naming conventions
- Add documentation for public APIs
- Use meaningful commit messages

---

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

**Kyra** - Making cross-platform data transfer simple and secure! 🚀
