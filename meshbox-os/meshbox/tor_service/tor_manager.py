"""
MeshBox Tor Manager — Manages Tor process, hidden service, and SOCKS5 connections.

Provides:
- Automatic Tor process lifecycle (start/stop via stem)
- Persistent v3 .onion hidden service tied to node identity
- SOCKS5 proxy connections to .onion addresses
- Connection status monitoring
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import socket
import subprocess
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger("meshbox.tor")

# Tor bootstrap phases — we wait until phase 100 (DONE)
_BOOTSTRAP_DONE = 100
_BOOTSTRAP_TIMEOUT = 120  # seconds


class TorManager:
    """Manages a local Tor process and hidden service for SANP communication.

    Attributes:
        onion_address: The v3 .onion address of this node (set after start).
        socks_port:    Local SOCKS5 proxy port.
        control_port:  Tor control port.
    """

    def __init__(
        self,
        data_dir: str | Path,
        socks_port: int = 9050,
        control_port: int = 9051,
        sanp_port: int = 7777,
    ) -> None:
        self.data_dir = Path(data_dir).expanduser().resolve()
        self.socks_port = socks_port
        self.control_port = control_port
        self.sanp_port = sanp_port

        self.onion_address: Optional[str] = None
        self._tor_process: Optional[subprocess.Popen] = None
        self._controller = None  # stem Controller
        self._running = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> str:
        """Start Tor, create hidden service, return the .onion address.

        Raises RuntimeError if Tor cannot be started or bootstrapped.
        """
        if self._running:
            return self.onion_address  # type: ignore[return-value]

        # Generate torrc
        from meshbox.tor_service.tor_config import generate_torrc

        torrc_path = generate_torrc(
            self.data_dir,
            socks_port=self.socks_port,
            control_port=self.control_port,
            hidden_service_port=self.sanp_port,
        )

        # Find tor binary
        tor_bin = shutil.which("tor")
        if tor_bin is None:
            raise RuntimeError(
                "Tor binary not found. Install Tor: apt install tor / brew install tor"
            )

        # Start Tor process
        logger.info("Starting Tor process…")
        self._tor_process = subprocess.Popen(
            [tor_bin, "-f", str(torrc_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

        # Wait for bootstrap
        await self._wait_for_bootstrap()

        # Connect stem controller
        await self._connect_controller()

        # Read onion address
        from meshbox.tor_service.tor_config import read_onion_address

        for _ in range(30):
            addr = read_onion_address(self.data_dir)
            if addr:
                self.onion_address = addr
                break
            await asyncio.sleep(1)

        if not self.onion_address:
            raise RuntimeError("Hidden service hostname not found after Tor start")

        self._running = True
        logger.info("Tor started — onion address: %s", self.onion_address)
        return self.onion_address

    async def stop(self) -> None:
        """Stop Tor gracefully."""
        self._running = False
        if self._controller:
            try:
                self._controller.close()
            except Exception:
                pass
            self._controller = None
        if self._tor_process:
            self._tor_process.terminate()
            try:
                self._tor_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._tor_process.kill()
            self._tor_process = None
        logger.info("Tor stopped")

    def is_tor_ready(self) -> bool:
        """Check if Tor is bootstrapped and the hidden service is available."""
        if not self._running or not self._controller:
            return False
        try:
            bootstrap = self._controller.get_info("status/bootstrap-phase")
            return "PROGRESS=100" in bootstrap
        except Exception:
            return False

    def get_onion_address(self) -> Optional[str]:
        """Return the .onion address or None if not started."""
        return self.onion_address

    # ------------------------------------------------------------------
    # Connections
    # ------------------------------------------------------------------

    async def connect_to_peer(
        self,
        onion_addr: str,
        port: int = 7777,
        timeout: float = 30.0,
    ) -> socket.socket:
        """Create a TCP socket connected to *onion_addr*:*port* via Tor SOCKS5.

        Returns the connected socket. Caller is responsible for closing it.
        """
        loop = asyncio.get_event_loop()
        sock = await loop.run_in_executor(
            None, self._socks5_connect, onion_addr, port, timeout
        )
        return sock

    def _socks5_connect(
        self, onion_addr: str, port: int, timeout: float
    ) -> socket.socket:
        """Blocking SOCKS5 connect through Tor proxy."""
        import socks  # PySocks

        sock = socks.socksocket()
        sock.set_proxy(socks.SOCKS5, "127.0.0.1", self.socks_port)
        sock.settimeout(timeout)
        sock.connect((onion_addr, port))
        return sock

    async def open_connection(
        self,
        onion_addr: str,
        port: int = 7777,
        timeout: float = 30.0,
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Open an asyncio stream pair to *onion_addr* via Tor SOCKS5.

        Returns (reader, writer) tuple for async I/O.
        """
        raw_sock = await self.connect_to_peer(onion_addr, port, timeout)
        loop = asyncio.get_event_loop()
        reader, writer = await asyncio.open_connection(sock=raw_sock)
        return reader, writer

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _wait_for_bootstrap(self) -> None:
        """Wait until Tor reports 100% bootstrap or timeout."""
        start = time.monotonic()
        while time.monotonic() - start < _BOOTSTRAP_TIMEOUT:
            if self._tor_process and self._tor_process.poll() is not None:
                raise RuntimeError(
                    f"Tor process exited with code {self._tor_process.returncode}"
                )
            # Check if control port is open
            try:
                s = socket.create_connection(
                    ("127.0.0.1", self.control_port), timeout=2
                )
                s.close()
                # Control port is up — now check bootstrap via stem
                try:
                    from stem.control import Controller

                    ctrl = Controller.from_port(
                        address="127.0.0.1", port=self.control_port
                    )
                    ctrl.authenticate()
                    phase = ctrl.get_info("status/bootstrap-phase")
                    ctrl.close()
                    if "PROGRESS=100" in phase:
                        logger.info("Tor bootstrap complete")
                        return
                except Exception:
                    pass
            except (ConnectionRefusedError, OSError):
                pass
            await asyncio.sleep(2)
        raise RuntimeError(f"Tor did not bootstrap within {_BOOTSTRAP_TIMEOUT}s")

    async def _connect_controller(self) -> None:
        """Connect the stem controller for status queries."""
        try:
            from stem.control import Controller

            self._controller = Controller.from_port(
                address="127.0.0.1", port=self.control_port
            )
            self._controller.authenticate()
            logger.info("Stem controller connected")
        except Exception as exc:
            logger.warning("Could not connect stem controller: %s", exc)
            self._controller = None

    def __del__(self) -> None:
        if self._tor_process and self._tor_process.poll() is None:
            self._tor_process.terminate()
