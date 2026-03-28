"""
MeshBox - Network manager.
Peer discovery and communication via WiFi and Bluetooth LE.
"""

import asyncio
import json
import logging
import socket
import struct
import sys
import time
from typing import Callable, Optional

logger = logging.getLogger("meshbox.network")

# Network ports and identifiers
MESHBOX_PORT = 4242
MESHBOX_DISCOVERY_PORT = 4243
MESHBOX_BLE_SERVICE_UUID = "12345678-1234-1234-1234-123456789abc"
MESHBOX_MAGIC = b"MBOX"
PROTOCOL_VERSION = 1


class PeerInfo:
    """Information about a discovered peer."""

    def __init__(self, fingerprint: str, address: str, port: int,
                 connection_type: str, profile_data: dict = None):
        self.fingerprint = fingerprint
        self.address = address
        self.port = port
        self.connection_type = connection_type  # "wifi" or "bluetooth"
        self.profile_data = profile_data or {}
        self.last_seen = time.time()

    def __repr__(self):
        return f"Peer({self.fingerprint[:8]}@{self.address}:{self.port})"


class WiFiDiscovery:
    """Peer discovery via WiFi (UDP broadcast)."""

    def __init__(self, profile_data: dict, port: int = MESHBOX_DISCOVERY_PORT):
        self.profile_data = profile_data
        self.port = port
        self.peers: dict[str, PeerInfo] = {}
        self.on_peer_discovered: Optional[Callable] = None
        self._running = False

    def _build_announce_packet(self) -> bytes:
        payload = json.dumps({
            "fingerprint": self.profile_data["fingerprint"],
            "name": self.profile_data["name"],
            "verify_key": self.profile_data["verify_key"],
            "box_public_key": self.profile_data["box_public_key"],
            "port": MESHBOX_PORT,
            "version": PROTOCOL_VERSION,
        }).encode("utf-8")

        header = MESHBOX_MAGIC + struct.pack("!BI", PROTOCOL_VERSION, len(payload))
        return header + payload

    def _parse_announce_packet(self, data: bytes, addr: str) -> Optional[PeerInfo]:
        if len(data) < 9 or data[:4] != MESHBOX_MAGIC:
            return None

        version = data[4]
        if version != PROTOCOL_VERSION:
            return None

        payload_len = struct.unpack("!I", data[5:9])[0]
        if len(data) < 9 + payload_len:
            return None

        try:
            payload = json.loads(data[9:9 + payload_len])
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

        if payload.get("fingerprint") == self.profile_data.get("fingerprint"):
            return None

        return PeerInfo(
            fingerprint=payload["fingerprint"],
            address=addr,
            port=payload.get("port", MESHBOX_PORT),
            connection_type="wifi",
            profile_data=payload,
        )

    async def start_announcer(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setblocking(False)

        packet = self._build_announce_packet()
        self._running = True
        logger.info("WiFi Discovery: broadcasting on port %d", self.port)

        while self._running:
            try:
                sock.sendto(packet, ("255.255.255.255", self.port))
            except OSError as e:
                logger.debug("Broadcast error: %s", e)

            await asyncio.sleep(5)

        sock.close()

    async def start_listener(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("", self.port))
        except OSError as e:
            logger.warning("Cannot bind discovery port %d: %s", self.port, e)
            return
        sock.setblocking(False)

        self._running = True
        logger.info("WiFi Discovery: listening on port %d", self.port)

        loop = asyncio.get_event_loop()
        while self._running:
            try:
                data, addr = await asyncio.wait_for(
                    loop.run_in_executor(None, lambda: sock.recvfrom(4096)),
                    timeout=1.0
                )
                peer = self._parse_announce_packet(data, addr[0])
                if peer:
                    self.peers[peer.fingerprint] = peer
                    if self.on_peer_discovered:
                        await self.on_peer_discovered(peer)
                    logger.debug("Peer discovered: %s", peer)
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.debug("Listener error: %s", e)
                await asyncio.sleep(1)

        sock.close()

    def stop(self):
        self._running = False


class MessageTransport:
    """TCP transport for message exchange between peers."""

    def __init__(self, local_fingerprint: str, port: int = MESHBOX_PORT):
        self.local_fingerprint = local_fingerprint
        self.port = port
        self.on_message_received: Optional[Callable] = None
        self.on_sync_request: Optional[Callable] = None
        self._server = None

    async def start_server(self):
        try:
            self._server = await asyncio.start_server(
                self._handle_connection, "0.0.0.0", self.port
            )
            logger.info("Transport: TCP server on port %d", self.port)
            async with self._server:
                await self._server.serve_forever()
        except OSError as e:
            logger.warning("Cannot bind TCP port %d: %s", self.port, e)

    async def _handle_connection(self, reader: asyncio.StreamReader,
                                  writer: asyncio.StreamWriter):
        addr = writer.get_extra_info("peername")
        logger.info("Incoming connection from %s", addr)

        try:
            header = await asyncio.wait_for(reader.readexactly(9), timeout=10)
            if header[:4] != MESHBOX_MAGIC:
                writer.close()
                return

            payload_len = struct.unpack("!I", header[5:9])[0]
            if payload_len > 10 * 1024 * 1024:
                writer.close()
                return

            data = await asyncio.wait_for(reader.readexactly(payload_len), timeout=30)
            request = json.loads(data)

            command = request.get("command")

            handlers = {
                "sync": self._handle_sync,
                "deliver": self._handle_deliver,
                "profile": self._handle_profile,
                "file": self._handle_file,
                "sos": self._handle_sos,
                "location": self._handle_location,
                "channel": self._handle_channel,
            }

            handler = handlers.get(command)
            if handler:
                response = await handler(request)
            else:
                response = {"status": "error", "message": "Unknown command"}

            resp_data = json.dumps(response).encode("utf-8")
            resp_header = MESHBOX_MAGIC + struct.pack("!BI", PROTOCOL_VERSION, len(resp_data))
            writer.write(resp_header + resp_data)
            await writer.drain()

        except Exception as e:
            logger.error("Connection error: %s", e)
        finally:
            writer.close()
            await writer.wait_closed()

    async def _handle_sync(self, request: dict) -> dict:
        if self.on_sync_request:
            return await self.on_sync_request(request)
        return {"status": "ok", "messages": []}

    async def _handle_deliver(self, request: dict) -> dict:
        if self.on_message_received:
            await self.on_message_received(request.get("message", {}))
        return {"status": "ok"}

    async def _handle_profile(self, request: dict) -> dict:
        return {"status": "ok"}

    async def _handle_file(self, request: dict) -> dict:
        if self.on_message_received:
            await self.on_message_received({"type": "file", **request.get("file", {})})
        return {"status": "ok"}

    async def _handle_sos(self, request: dict) -> dict:
        if self.on_message_received:
            await self.on_message_received({"type": "sos", **request.get("alert", {})})
        return {"status": "ok"}

    async def _handle_location(self, request: dict) -> dict:
        if self.on_message_received:
            await self.on_message_received({"type": "location", **request.get("location", {})})
        return {"status": "ok"}

    async def _handle_channel(self, request: dict) -> dict:
        if self.on_message_received:
            await self.on_message_received({"type": "channel", **request.get("message", {})})
        return {"status": "ok"}

    async def send_to_peer(self, peer: PeerInfo, command: str, payload: dict) -> Optional[dict]:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(peer.address, peer.port),
                timeout=10
            )

            request = {"command": command, **payload}
            data = json.dumps(request).encode("utf-8")
            header = MESHBOX_MAGIC + struct.pack("!BI", PROTOCOL_VERSION, len(data))

            writer.write(header + data)
            await writer.drain()

            resp_header = await asyncio.wait_for(reader.readexactly(9), timeout=10)
            resp_len = struct.unpack("!I", resp_header[5:9])[0]
            resp_data = await asyncio.wait_for(reader.readexactly(resp_len), timeout=30)

            writer.close()
            await writer.wait_closed()

            return json.loads(resp_data)

        except Exception as e:
            logger.error("Error sending to %s: %s", peer, e)
            return None


class BluetoothDiscovery:
    """Peer discovery via Bluetooth Low Energy (BLE)."""

    def __init__(self, profile_data: dict):
        self.profile_data = profile_data
        self.peers: dict[str, PeerInfo] = {}
        self.on_peer_discovered: Optional[Callable] = None
        self._running = False

    async def start_advertising(self):
        """Start BLE advertising (Linux only, requires bluetoothctl)."""
        if sys.platform == "darwin":
            logger.info("BLE advertising disabled on macOS (no Bluetooth permission for daemon)")
            return

        self._running = True
        adv_name = f"MB-{self.profile_data['fingerprint'][:8]}"
        logger.info("BLE: advertising as '%s'", adv_name)

        while self._running:
            try:
                import subprocess
                subprocess.run(
                    ["bluetoothctl", "system-alias", adv_name],
                    capture_output=True, timeout=5
                )
                subprocess.run(
                    ["bluetoothctl", "discoverable", "on"],
                    capture_output=True, timeout=5
                )
            except (FileNotFoundError, Exception) as e:
                logger.debug("BLE advertising not available: %s", e)

            await asyncio.sleep(10)

    async def start_scanner(self):
        """Scan for nearby BLE devices."""
        if sys.platform == "darwin":
            logger.info("BLE scanning disabled on macOS (TCC requires Bluetooth permission in Info.plist)")
            return

        self._running = True

        try:
            from bleak import BleakScanner
        except ImportError:
            logger.info("BLE scanning not available (bleak not installed)")
            return

        logger.info("BLE: scanning started")

        while self._running:
            try:
                devices = await BleakScanner.discover(timeout=5.0)
                for device in devices:
                    name = device.name or ""
                    if name.startswith("MB-"):
                        fingerprint_prefix = name[3:]
                        peer = PeerInfo(
                            fingerprint=fingerprint_prefix,
                            address=device.address,
                            port=0,
                            connection_type="bluetooth",
                        )
                        is_new = fingerprint_prefix not in self.peers
                        self.peers[fingerprint_prefix] = peer
                        if is_new and self.on_peer_discovered:
                            await self.on_peer_discovered(peer)
                        logger.debug("BLE peer: %s (%s)", name, device.address)
            except Exception as e:
                logger.debug("BLE scan error: %s", e)

            await asyncio.sleep(10)

    def stop(self):
        self._running = False


class NetworkManager:
    """Main network manager - coordinates WiFi and Bluetooth."""

    def __init__(self, profile_data: dict):
        self.profile_data = profile_data
        self.wifi_discovery = WiFiDiscovery(profile_data)
        self.bt_discovery = BluetoothDiscovery(profile_data)
        self.transport = MessageTransport(profile_data["fingerprint"])
        self.all_peers: dict[str, PeerInfo] = {}
        self.on_peer_discovered: Optional[Callable] = None
        self.on_message_received: Optional[Callable] = None

    async def _on_wifi_peer(self, peer: PeerInfo):
        is_new = peer.fingerprint not in self.all_peers
        self.all_peers[peer.fingerprint] = peer
        if is_new and self.on_peer_discovered:
            await self.on_peer_discovered(peer)

    async def _on_bt_peer(self, peer: PeerInfo):
        is_new = peer.fingerprint not in self.all_peers
        self.all_peers[peer.fingerprint] = peer
        if is_new and self.on_peer_discovered:
            await self.on_peer_discovered(peer)

    async def start(self):
        self.wifi_discovery.on_peer_discovered = self._on_wifi_peer
        self.bt_discovery.on_peer_discovered = self._on_bt_peer

        if self.on_message_received:
            self.transport.on_message_received = self.on_message_received

        tasks = [
            asyncio.create_task(self.wifi_discovery.start_announcer()),
            asyncio.create_task(self.wifi_discovery.start_listener()),
            asyncio.create_task(self.bt_discovery.start_advertising()),
            asyncio.create_task(self.bt_discovery.start_scanner()),
            asyncio.create_task(self.transport.start_server()),
        ]

        await asyncio.gather(*tasks, return_exceptions=True)

    def stop(self):
        self.wifi_discovery.stop()
        self.bt_discovery.stop()

    def get_peers(self) -> list[PeerInfo]:
        now = time.time()
        active = {
            fp: p for fp, p in self.all_peers.items()
            if now - p.last_seen < 60
        }
        self.all_peers = active
        return list(active.values())
