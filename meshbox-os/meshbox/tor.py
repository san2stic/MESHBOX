"""
MeshBox - Tor integration v4.
Manages Tor hidden service for internet-based peer-to-peer communication.
- Tor hidden service for inbound connections
- SOCKS5 proxy for outbound connections to .onion peers
- Message transport over Tor (same protocol as TCP)
"""

import asyncio
import json
import logging
import os
import struct
import time
from pathlib import Path
from typing import Optional

from meshbox.config import (
    TOR_SOCKS_PORT, TOR_CONTROL_PORT,
    TOR_DATA_DIR, TOR_HIDDEN_SERVICE_DIR,
)
from meshbox.network import (
    MESHBOX_MAGIC, MESHBOX_PORT, PROTOCOL_VERSION, MAX_PAYLOAD_SIZE,
)

logger = logging.getLogger("meshbox.tor")


class TorManager:
    """Manage Tor hidden service and SOCKS5 transport for MeshBox."""

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.tor_data_dir = TOR_DATA_DIR
        self.hs_dir = TOR_HIDDEN_SERVICE_DIR
        self.onion_address: Optional[str] = None
        self._controller = None
        self._running = False
        self._server = None

    async def start(self) -> bool:
        """Start Tor hidden service. Returns True if successful."""
        try:
            from stem.control import Controller
        except ImportError:
            logger.warning("stem not installed - Tor support disabled")
            return False

        try:
            self._controller = Controller.from_port(port=TOR_CONTROL_PORT)
            self._controller.authenticate()

            # Load saved key for persistent .onion address, or create new
            key_file = self.data_dir / "tor_hidden_service_key"
            key_type = "NEW"
            key_content = "ED25519-V3"

            if key_file.exists():
                saved = key_file.read_text().strip()
                key_type = "ED25519-V3"
                key_content = saved
                logger.info("Loaded existing Tor hidden service key")

            result = self._controller.create_ephemeral_hidden_service(
                {80: f"127.0.0.1:{MESHBOX_PORT}"},
                await_publication=True,
                key_type=key_type,
                key_content=key_content,
            )
            self.onion_address = result.service_id + ".onion"
            self._running = True

            # Save private key for persistence across restarts
            if not key_file.exists() and hasattr(result, 'private_key'):
                key_file.parent.mkdir(parents=True, exist_ok=True)
                key_file.write_text(result.private_key)
                key_file.chmod(0o600)
                logger.info("Saved Tor hidden service key for persistence")

            logger.info("Tor hidden service started: %s", self.onion_address)

            # Save onion address for reference
            onion_file = self.data_dir / "onion_address"
            onion_file.write_text(self.onion_address)

            return True

        except Exception as e:
            logger.error("Failed to start Tor: %s", e)
            return False

    def stop(self):
        """Stop Tor hidden service."""
        self._running = False
        if self._controller:
            try:
                if self.onion_address:
                    service_id = self.onion_address.replace(".onion", "")
                    self._controller.remove_ephemeral_hidden_service(service_id)
                self._controller.close()
            except Exception as e:
                logger.debug("Error stopping Tor: %s", e)
            self._controller = None

    async def send_to_onion(self, fingerprint_or_onion: str,
                             command: str, payload: dict) -> Optional[dict]:
        """
        Send a message to a .onion address via Tor SOCKS5 proxy.
        Can accept either a fingerprint (looks up in DB) or direct .onion address.
        """
        try:
            import socks
        except ImportError:
            logger.warning("PySocks not installed - cannot send via Tor")
            return None

        onion_addr = fingerprint_or_onion
        if not fingerprint_or_onion.endswith(".onion"):
            # Look up from storage (caller should provide .onion or store mapping)
            logger.debug("Cannot resolve fingerprint %s to onion (not implemented here)",
                        fingerprint_or_onion)
            return None

        try:
            # Connect via Tor SOCKS5 proxy
            reader, writer = await asyncio.wait_for(
                self._open_tor_connection(onion_addr, 80),
                timeout=30  # Tor connections are slower
            )

            request = {"command": command, **payload}
            data = json.dumps(request).encode("utf-8")
            header = MESHBOX_MAGIC + struct.pack("!BI", PROTOCOL_VERSION, len(data))

            writer.write(header + data)
            await writer.drain()

            resp_header = await asyncio.wait_for(reader.readexactly(9), timeout=30)
            resp_len = struct.unpack("!I", resp_header[5:9])[0]
            if resp_len > MAX_PAYLOAD_SIZE:
                writer.close()
                await writer.wait_closed()
                return None

            resp_data = await asyncio.wait_for(reader.readexactly(resp_len), timeout=60)

            writer.close()
            await writer.wait_closed()

            return json.loads(resp_data)

        except Exception as e:
            logger.error("Tor send to %s failed: %s", onion_addr[:16], e)
            return None

    async def _open_tor_connection(self, onion_addr: str, port: int):
        """Open a connection through Tor SOCKS5 proxy."""
        import socks
        import socket

        sock = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
        sock.set_proxy(socks.SOCKS5, "127.0.0.1", TOR_SOCKS_PORT)
        sock.settimeout(30)

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, sock.connect, (onion_addr, port))

        reader, writer = await asyncio.open_connection(sock=sock)
        return reader, writer

    def is_available(self) -> bool:
        """Check if Tor is running and our hidden service is active."""
        if not self._running or not self._controller:
            return False
        try:
            self._controller.get_info("status/circuit-established")
            return True
        except Exception:
            return False

    def get_status(self) -> dict:
        """Get Tor connection status."""
        status = {
            "running": self._running,
            "onion_address": self.onion_address,
            "available": self.is_available(),
        }
        if self._controller:
            try:
                status["circuit_established"] = (
                    self._controller.get_info("status/circuit-established") == "1"
                )
                status["bytes_read"] = self._controller.get_info("traffic/read")
                status["bytes_written"] = self._controller.get_info("traffic/written")
            except Exception:
                pass
        return status
