#!/bin/bash

# Anti-DDoS Protection System - Linux Installer
# ==============================================

set -e

INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/antiddos"
DATA_DIR="/var/lib/antiddos"
LOG_DIR="/var/log/antiddos"
SERVICE_DIR="/etc/systemd/system"
EBPF_DIR="/usr/lib/antiddos"

echo "============================================="
echo "  Anti-DDoS Protection System Installer"
echo "============================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: Please run as root (sudo)"
    exit 1
fi

# Check dependencies
echo "Checking dependencies..."

check_command() {
    if ! command -v "$1" &> /dev/null; then
        echo "Error: $1 is required but not installed"
        exit 1
    fi
}

check_command g++
check_command cmake
check_command make
check_command iptables

# Check for eBPF support
if uname -r | grep -qE '^4\.(1[8-9]|[2-9][0-9])|^5\.|^6\.'; then
    echo "eBPF/XDP supported"
    EBPF_SUPPORT=true
else
    echo "Warning: eBPF/XDP not supported (requires Linux 4.18+)"
    EBPF_SUPPORT=false
fi

echo "Dependencies OK"
echo ""

# Create directories
echo "Creating directories..."
mkdir -p "$CONFIG_DIR"
mkdir -p "$DATA_DIR"
mkdir -p "$LOG_DIR"
mkdir -p "$EBPF_DIR"

# Build project
echo "Building project..."
mkdir -p build
cd build
cmake .. 2>/dev/null
make -j$(nproc) 2>/dev/null
cd ..

# Check if binaries were built
if [ ! -f "bin/antiddos-cli" ]; then
    echo "Error: Build failed - bin/antiddos-cli not found"
    exit 1
fi

# Install binaries
echo "Installing binaries..."
cp bin/antiddos-cli "$INSTALL_DIR/"
cp bin/antiddos-daemon "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/antiddos-cli"
chmod +x "$INSTALL_DIR/antiddos-daemon"

# Install eBPF/XDP binaries if available
if [ "$EBPF_SUPPORT" = true ] && [ -f "bin/xdp-cli" ]; then
    cp bin/xdp-cli "$INSTALL_DIR/"
    cp bin/xdp-loader "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/xdp-cli"
    chmod +x "$INSTALL_DIR/xdp-loader"
    
    # Install eBPF object file
    if [ -f "phase5-ebpf-xdp/src/xdp_filter_kern.o" ]; then
        cp phase5-ebpf-xdp/src/xdp_filter_kern.o "$EBPF_DIR/"
    fi
    
    echo "eBPF/XDP support installed"
fi

# Install configuration
echo "Installing configuration..."
cp config/config.ini "$CONFIG_DIR/"

# Create systemd service
echo "Creating systemd service..."
cat > "$SERVICE_DIR/antiddos.service" << EOF
[Unit]
Description=Anti-DDoS Protection Service
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/antiddos-daemon
Restart=always
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable antiddos

echo ""
echo "============================================="
echo "  Installation Complete!"
echo "============================================="
echo ""
echo "Installed binaries:"
echo "  $INSTALL_DIR/antiddos-cli    - Main CLI"
echo "  $INSTALL_DIR/antiddos-daemon - Service daemon"

if [ "$EBPF_SUPPORT" = true ]; then
    echo "  $INSTALL_DIR/xdp-cli         - eBPF/XDP CLI"
    echo "  $INSTALL_DIR/xdp-loader      - eBPF/XDP Loader"
fi

echo ""
echo "Usage:"
echo "  Start:     sudo systemctl start antiddos"
echo "  Stop:      sudo systemctl stop antiddos"
echo "  Status:    sudo systemctl status antiddos"
echo "  CLI:       antiddos-cli help"

if [ "$EBPF_SUPPORT" = true ]; then
    echo "  XDP:       xdp-cli help"
fi

echo ""
echo "Configuration: $CONFIG_DIR/config.ini"
echo "Logs: $LOG_DIR/antiddos.log"
echo ""