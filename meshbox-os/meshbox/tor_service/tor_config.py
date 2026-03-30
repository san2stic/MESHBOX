"""
MeshBox Tor Configuration — Generates minimal torrc for hidden services.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional


DEFAULT_SOCKS_PORT = 9050
DEFAULT_CONTROL_PORT = 9051
DEFAULT_SANP_PORT = 7777


def generate_torrc(
    data_dir: str | Path,
    socks_port: int = DEFAULT_SOCKS_PORT,
    control_port: int = DEFAULT_CONTROL_PORT,
    hidden_service_port: int = DEFAULT_SANP_PORT,
    local_bind_port: int | None = None,
) -> Path:
    """Generate a minimal torrc and return its path.

    Parameters
    ----------
    data_dir : path
        Root data directory (e.g. ``~/.meshbox``).
    socks_port : int
        SOCKS5 proxy port Tor listens on.
    control_port : int
        Tor control port for stem communication.
    hidden_service_port : int
        Virtual port exposed by the hidden service.
    local_bind_port : int or None
        Local TCP port the hidden service forwards to.
        Defaults to *hidden_service_port*.
    """
    data_dir = Path(data_dir).expanduser().resolve()
    tor_dir = data_dir / "tor"
    tor_dir.mkdir(parents=True, exist_ok=True)

    hs_dir = tor_dir / "hidden_service"
    hs_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(hs_dir, 0o700)

    local_bind = local_bind_port or hidden_service_port

    torrc_content = f"""\
# MeshBox auto-generated torrc
SocksPort {socks_port}
ControlPort {control_port}
CookieAuthentication 1

DataDirectory {tor_dir}

# Hidden service for SANP protocol
HiddenServiceDir {hs_dir}
HiddenServicePort {hidden_service_port} 127.0.0.1:{local_bind}
HiddenServiceVersion 3

# Hardened defaults
SafeLogging 1
AvoidDiskWrites 1
"""

    torrc_path = tor_dir / "torrc"
    torrc_path.write_text(torrc_content)
    os.chmod(torrc_path, 0o600)
    return torrc_path


def read_onion_address(data_dir: str | Path) -> Optional[str]:
    """Read the .onion hostname from the hidden service directory."""
    hostname_path = (
        Path(data_dir).expanduser() / "tor" / "hidden_service" / "hostname"
    )
    if hostname_path.exists():
        return hostname_path.read_text().strip()
    return None
