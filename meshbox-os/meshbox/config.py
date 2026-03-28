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

# Max file size (10 MB)
MAX_FILE_SIZE = 10 * 1024 * 1024
