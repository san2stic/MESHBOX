"""
MeshBox - Cross-platform configuration and path management.
Data directory defaults to ~/.meshbox/ and can be overridden via MESHBOX_DATA_DIR.
"""

import os
from pathlib import Path


def get_data_dir() -> Path:
    """Return the MeshBox data directory (cross-platform)."""
    env = os.environ.get("MESHBOX_DATA_DIR")
    if env:
        return Path(env)
    return Path.home() / ".meshbox"


DATA_DIR = get_data_dir()

# Default network ports
MESH_PORT = 4242
DISCOVERY_PORT = 4243

# Default message TTL (7 days)
DEFAULT_TTL = 604800

# Default web UI port
WEB_PORT = 8080

# Max file size (50 MB with chunking)
MAX_FILE_SIZE = 50 * 1024 * 1024

# File chunk size for mesh relay (256 KB)
FILE_CHUNK_SIZE = 256 * 1024

# Tor configuration
TOR_SOCKS_PORT = 9050
TOR_CONTROL_PORT = 9051
TOR_DATA_DIR = DATA_DIR / "tor"
TOR_HIDDEN_SERVICE_DIR = TOR_DATA_DIR / "hidden_service"
TOR_ENABLED_DEFAULT = True

# MeshBox directory bootstrap nodes (.onion addresses)
# These are well-known directory nodes that help with Tor peer discovery.
# Any MeshBox node can optionally act as a directory node.
DIRECTORY_BOOTSTRAP_NODES = [
    # Placeholder bootstrap nodes - replace with real .onion addresses in production
    # "meshboxdir1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.onion",
    # "meshboxdir2xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.onion",
]

# Directory announcement interval (seconds)
DIRECTORY_ANNOUNCE_INTERVAL = 300  # 5 minutes

# Peer stale timeout (seconds)
PEER_STALE_TIMEOUT = 1800  # 30 minutes

# Update configuration
UPDATE_CHECK_INTERVAL = 86400  # 24 hours
UPDATE_TRUSTED_KEYS = []  # Ed25519 public keys for signed releases

# --- v4.1 Network enhancements ---

# mDNS / Zeroconf service type for mesh peer discovery
MDNS_SERVICE_TYPE = "_meshbox._tcp.local."

# Multicast group for discovery (link-local, routers won't forward)
MULTICAST_GROUP = "239.77.66.88"

# WiFi discovery announce interval (seconds)
DISCOVERY_ANNOUNCE_INTERVAL = 5

# TCP connection pool: max idle connections per peer
CONNECTION_POOL_MAX_IDLE = 4
CONNECTION_POOL_IDLE_TIMEOUT = 120  # seconds

# Gossip interval (seconds): how often we share peer lists with neighbors
GOSSIP_INTERVAL = 180  # 3 minutes

# Message priority levels (lower = higher priority)
PRIORITY_SOS = 0
PRIORITY_RECEIPT = 1
PRIORITY_DIRECT = 2
PRIORITY_CHANNEL = 3
PRIORITY_FILE = 4
PRIORITY_RELAY = 5

# Inventory sync: use compact hashes instead of full relay dumps
SYNC_INVENTORY_HASH_LEN = 12  # bytes of message_id hash in inventory bloom

# Network stats persistence interval (seconds)
NETWORK_STATS_SAVE_INTERVAL = 300
