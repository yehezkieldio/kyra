#!/bin/bash

# Kyra Daemon Installation Script for Linux
# Run as root: sudo ./install-daemon.sh

set -e

KYRA_USER="kyra"
KYRA_GROUP="kyra"
KYRA_HOME="/home/kyra"
CONFIG_DIR="${KYRA_HOME}/.config/kyra"
DOWNLOAD_DIR="${KYRA_HOME}/Downloads/kyra"
LOG_DIR="/var/log/kyra"
BINARY_PATH="/usr/local/bin/kyra-daemon"
SERVICE_PATH="/etc/systemd/system/kyra-daemon.service"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   print_error "This script must be run as root (use sudo)"
   exit 1
fi

# Check if binary exists
if [[ ! -f "target/release/kyra-daemon" ]]; then
    print_error "kyra-daemon binary not found. Please run 'cargo build --release' first."
    exit 1
fi

print_status "Installing Kyra Daemon..."

# Create kyra user if it doesn't exist
if ! id "$KYRA_USER" &>/dev/null; then
    print_status "Creating kyra user..."
    useradd -r -s /bin/false -d "$KYRA_HOME" "$KYRA_USER"
else
    print_status "User $KYRA_USER already exists"
fi

# Create directories
print_status "Creating directories..."
mkdir -p "$CONFIG_DIR"
mkdir -p "$DOWNLOAD_DIR"
mkdir -p "$LOG_DIR"

# Set ownership
chown -R "${KYRA_USER}:${KYRA_GROUP}" "$KYRA_HOME"
chown -R "${KYRA_USER}:${KYRA_GROUP}" "$LOG_DIR"

# Copy binary
print_status "Installing binary..."
cp "target/release/kyra-daemon" "$BINARY_PATH"
chmod +x "$BINARY_PATH"

# Install systemd service
print_status "Installing systemd service..."
cp "systemd/kyra-daemon.service" "$SERVICE_PATH"

# Create default configuration if it doesn't exist
CONFIG_FILE="${CONFIG_DIR}/daemon.toml"
if [[ ! -f "$CONFIG_FILE" ]]; then
    print_status "Creating default configuration..."
    cat > "$CONFIG_FILE" << EOF
[network]
host = "0.0.0.0"
port = 8080
enable_tls = false

[security]
require_auth = false
allowed_hosts = ["127.0.0.1", "::1", "192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"]

[storage]
download_dir = "${DOWNLOAD_DIR}"
max_file_size = 10737418240  # 10GB
enable_compression = true

[logging]
level = "info"
file = "${LOG_DIR}/daemon.log"

[discovery]
enable_mdns = true
service_name = "kyra-daemon"
fallback_hosts = []
announce_interval = 30
EOF
    chown "${KYRA_USER}:${KYRA_GROUP}" "$CONFIG_FILE"
    print_status "Default configuration created at $CONFIG_FILE"
else
    print_warning "Configuration file already exists at $CONFIG_FILE"
fi

# Reload systemd
print_status "Reloading systemd..."
systemctl daemon-reload

# Enable service
print_status "Enabling kyra-daemon service..."
systemctl enable kyra-daemon

print_status "Installation completed successfully!"
print_status ""
print_status "Next steps:"
print_status "1. Review configuration: $CONFIG_FILE"
print_status "2. Start the service: sudo systemctl start kyra-daemon"
print_status "3. Check status: sudo systemctl status kyra-daemon"
print_status "4. View logs: sudo journalctl -u kyra-daemon -f"
print_status ""
print_status "Security recommendations:"
print_status "- Configure authentication: kyra-agent auth generate-token 'your-passphrase'"
print_status "- Enable TLS encryption for production use"
print_status "- Review allowed_hosts configuration"

print_warning "Don't forget to install kyra-agent on client machines!"
