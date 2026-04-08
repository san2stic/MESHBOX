"""
MeshBox - Cross-platform configuration and path management.
Data directory defaults to ~/.meshbox/ and can be overridden via MESHBOX_DATA_DIR.

SANP protocol v5.0 — all communication goes through Tor hidden services.
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

# ── SANP Protocol ──────────────────────────────────────────────
SANP_PORT = 7777           # SANP TCP protocol port (over Tor)
API_PORT = 8080            # REST API (local only)
API_HOST = "127.0.0.1"    # REST API bind address
SANP_VERSION = 1           # SANP wire protocol version

# ── Legacy network ports (kept for backward compatibility) ─────
MESH_PORT = 4242
DISCOVERY_PORT = 4243

# ── Message settings ───────────────────────────────────────────
DEFAULT_TTL = 604800       # 7 days

# ── Web UI ─────────────────────────────────────────────────────
WEB_PORT = 8080

# ── File sharing ───────────────────────────────────────────────
MAX_FILE_SIZE = 50 * 1024 * 1024   # 50 MB
FILE_CHUNK_SIZE = 256 * 1024       # 256 KB

# ── Tor configuration ─────────────────────────────────────────
TOR_SOCKS_PORT = 9050
TOR_CONTROL_PORT = 9051
TOR_DATA_DIR = DATA_DIR / "tor"
TOR_HIDDEN_SERVICE_DIR = TOR_DATA_DIR / "hidden_service"
TOR_ENABLED_DEFAULT = True

# ── Directory / bootstrap ─────────────────────────────────────
DIRECTORY_BOOTSTRAP_NODES = []
DIRECTORY_ANNOUNCE_INTERVAL = 300  # 5 minutes

# ── Peer management ───────────────────────────────────────────
PEER_STALE_TIMEOUT = 1800         # 30 minutes
MAX_PEERS = 8
MIN_PEERS = 3

# ── Gossip ─────────────────────────────────────────────────────
GOSSIP_FANOUT = 3
GOSSIP_INTERVAL = 180             # 3 minutes

# ── SANP gossip topics ────────────────────────────────────────
TOPIC_PEER_ANNOUNCE = "peer_announce"
TOPIC_SOS_ALERT = "sos_alert"
TOPIC_CHANNEL_MESSAGE = "channel_message"
TOPIC_FILE_SHARE = "file_share"

# ── Update configuration ──────────────────────────────────────
UPDATE_CHECK_INTERVAL = 86400     # 24 hours
UPDATE_TRUSTED_KEYS = []

# ── Legacy discovery (WiFi/BT mesh) ───────────────────────────
MDNS_SERVICE_TYPE = "_meshbox._tcp.local."
MULTICAST_GROUP = "239.77.66.88"
DISCOVERY_ANNOUNCE_INTERVAL = 5
CONNECTION_POOL_MAX_IDLE = 4
CONNECTION_POOL_IDLE_TIMEOUT = 120

# ── Message priority levels ───────────────────────────────────
PRIORITY_SOS = 0
PRIORITY_RECEIPT = 1
PRIORITY_DIRECT = 2
PRIORITY_CHANNEL = 3
PRIORITY_FILE = 4
PRIORITY_RELAY = 5

# ── Sync ───────────────────────────────────────────────────────
SYNC_INVENTORY_HASH_LEN = 12
NETWORK_STATS_SAVE_INTERVAL = 300

# ── Routing ────────────────────────────────────────────────────
ROUTE_EXPIRE_SECONDS = 600        # 10 minutes
MAX_HOPS = 20                     # max routing hops

# ── Keepalive ──────────────────────────────────────────────────
KEEPALIVE_INTERVAL = 60           # seconds
ROUTE_BROADCAST_INTERVAL = 120    # seconds
PEER_DISCOVERY_INTERVAL = 300    # seconds
CLEANUP_INTERVAL = 180           # seconds

# ── Circuit Breaker ────────────────────────────────────────────
CIRCUIT_BREAKER_ENABLED = True
CB_FAILURE_THRESHOLD = 5          # failures before opening circuit
CB_RECOVERY_TIMEOUT = 30          # seconds before trying HALF_OPEN
CB_HALF_OPEN_PROBE_COUNT = 3      # probes needed to close circuit
CB_WINDOW_SIZE = 60              # sliding window in seconds

# ── Adaptive Rate Limiting ───────────────────────────────────────
RATE_LIMIT_ADAPTIVE = True
RATE_LIMIT_BASE_REFILLS_PER_SEC = 10
RATE_LIMIT_MIN_REFILLS_PER_SEC = 1
RATE_LIMIT_MAX_REFILLS_PER_SEC = 100
RATE_LIMIT_CONGESTION_THRESHOLD = 1000  # queue depth for tightening
RATE_LIMIT_LATENCY_THRESHOLD_MS = 100   # latency for tightening

# ── Priority-based rate limits ──────────────────────────────────
RATE_LIMIT_SOS_PER_MIN = 500
RATE_LIMIT_RECEIPT_PER_MIN = 500
RATE_LIMIT_DIRECT_PER_MIN = 100
RATE_LIMIT_CHANNEL_PER_MIN = 50
RATE_LIMIT_FILE_PER_MIN = 20
RATE_LIMIT_RELAY_PER_MIN = 30
