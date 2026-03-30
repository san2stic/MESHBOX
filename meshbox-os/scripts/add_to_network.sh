#!/usr/bin/env bash
# MeshBox — Join an existing network by connecting to seed nodes
set -euo pipefail

SEED_FILE="${1:-}"

echo "╔══════════════════════════════════════════╗"
echo "║    MESHBOX — Join Network                ║"
echo "╚══════════════════════════════════════════╝"

# Check if meshbox is installed
if ! command -v meshbox &>/dev/null; then
    echo "Error: meshbox is not installed. Run install_meshbox.sh first."
    exit 1
fi

# Check if Tor is running
if ! systemctl is-active --quiet tor 2>/dev/null; then
    if ! pgrep -x tor >/dev/null 2>&1; then
        echo "Warning: Tor does not appear to be running."
        echo "Start it with: sudo systemctl start tor  (or: brew services start tor)"
    fi
fi

if [[ -n "$SEED_FILE" && -f "$SEED_FILE" ]]; then
    echo "Using seed file: $SEED_FILE"
    SEEDS=$(cat "$SEED_FILE" | tr '\n' ',' | sed 's/,$//')
    echo "Seeds: $SEEDS"
    echo ""
    echo "Starting MeshBox with custom seeds…"
    meshbox start --seeds "$SEEDS"
else
    echo "No seed file provided. Starting with default bootstrap…"
    echo ""
    echo "To join a specific network, provide a seed file:"
    echo "  $0 /path/to/seeds.txt"
    echo ""
    echo "Seed file format (one per line):"
    echo "  xxxxxxxx.onion:7777"
    echo ""
    meshbox start
fi
