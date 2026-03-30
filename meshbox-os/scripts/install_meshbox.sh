#!/usr/bin/env bash
# MeshBox — Install script for Ubuntu/Debian systems
set -euo pipefail

echo "╔══════════════════════════════════════════╗"
echo "║       MESHBOX INSTALLER v1.0             ║"
echo "╚══════════════════════════════════════════╝"

# Check for root
if [[ $EUID -ne 0 ]]; then
    echo "This script should be run as root (or with sudo)."
    exit 1
fi

# Install system dependencies
echo "[1/5] Installing system dependencies…"
apt-get update -qq
apt-get install -y -qq python3 python3-pip python3-venv tor

# Enable and start Tor
echo "[2/5] Configuring Tor…"
systemctl enable tor
systemctl start tor

# Create meshbox user if it doesn't exist
echo "[3/5] Setting up meshbox user…"
if ! id -u meshbox >/dev/null 2>&1; then
    useradd -m -s /bin/bash meshbox
fi

# Install Python packages
echo "[4/5] Installing Python dependencies…"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

if [[ -f "$REPO_DIR/requirements.txt" ]]; then
    pip3 install -r "$REPO_DIR/requirements.txt"
else
    pip3 install PyNaCl msgpack stem fastapi uvicorn click aiohttp pydantic PySocks python-dotenv
fi

# Install meshbox package
echo "[5/5] Installing MeshBox…"
pip3 install -e "$REPO_DIR"

echo ""
echo "✓ MeshBox installed successfully!"
echo ""
echo "Usage:"
echo "  meshbox start         — Start the mesh daemon"
echo "  meshbox status        — Show node status"
echo "  meshbox peers list    — List connected peers"
echo ""
echo "Data directory: ~/.meshbox/"
