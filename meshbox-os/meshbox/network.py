"""
MeshBox - Network manager v4.
Peer discovery and communication via WiFi, Bluetooth LE, and Tor.
Features:
- WiFi UDP broadcast discovery
- Bluetooth LE scanning
- Tor hidden service transport (internet-based P2P)
- TCP message transport with framing
- Onion routing for multi-hop sender privacy
- Message deduplication (seen set)
- Hop-limited epidemic routing
- Rate limiting & connection throttling
- Connection retry with exponential backoff
- Delivery receipts
- Bandwidth throttling
"""

import asyncio
import hashlib
import json
import logging
import os
import socket
import struct
import sys
import time
from collections import defaultdict
from typing import Callable, Optional

import nacl.encoding
import nacl.public
import nacl.utils

from meshbox.config import PEER_STALE_TIMEOUT

logger = logging.getLogger("meshbox.network")

# Network ports and identifiers
MESHBOX_PORT = 4242
MESHBOX_DISCOVERY_PORT = 4243
MESHBOX_BLE_SERVICE_UUID = "12345678-1234-1234-1234-123456789abc"
MESHBOX_MAGIC = b"MBOX"
PROTOCOL_VERSION = 3

# Routing limits
MAX_HOP_COUNT = 10
DEFAULT_TTL = 604800  # 7 days
MAX_PAYLOAD_SIZE = 50 * 1024 * 1024  # 50 MB (increased for file chunking)

# Rate limiting
MAX_CONNECTIONS_PER_IP = 20  # per minute
MAX_MESSAGES_PER_PEER = 100  # per minute

# Retry constants
MAX_SEND_RETRIES = 3
RETRY_BASE_DELAY = 1.0  # seconds, doubles each retry

# Bandwidth throttle (bytes/sec, 0 = unlimited)
BANDWIDTH_LIMIT = 0


class RateLimiter:
    """Token bucket rate limiter per IP / per peer."""

    def __init__(self, max_requests: int = 60, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window = window_seconds
        self._buckets: dict[str, list[float]] = defaultdict(list)

    def allow(self, key: str) -> bool:
        """Check if a request from this key is allowed."""
        now = time.time()
        bucket = self._buckets[key]

        # Remove expired entries
        self._buckets[key] = [t for t in bucket if now - t < self.window]
        bucket = self._buckets[key]

        if len(bucket) >= self.max_requests:
            return False

        bucket.append(now)
        return True

    def cleanup(self):
        """Remove empty buckets."""
        now = time.time()
        empty_keys = [
            k for k, v in self._buckets.items()
            if all(now - t >= self.window for t in v)
        ]
        for k in empty_keys:
            del self._buckets[k]


class MessageDeduplicator:
    """
    Track seen message IDs to prevent duplicate processing and infinite relay loops.
    Uses a combination of a set and age-based expiration.
    """

    def __init__(self, max_size: int = 50000, ttl: int = DEFAULT_TTL):
        self.max_size = max_size
        self.ttl = ttl
        self._seen: dict[str, float] = {}  # message_id -> first_seen_timestamp

    def is_duplicate(self, message_id: str) -> bool:
        """Returns True if this message was already seen."""
        now = time.time()

        # Cleanup expired entries periodically
        if len(self._seen) > self.max_size:
            self._cleanup(now)

        if message_id in self._seen:
            return True

        self._seen[message_id] = now
        return False

    def mark_seen(self, message_id: str):
        """Explicitly mark a message as seen."""
        self._seen[message_id] = time.time()

    def _cleanup(self, now: float):
        """Remove expired entries."""
        expired = [
            mid for mid, ts in self._seen.items()
            if now - ts > self.ttl
        ]
        for mid in expired:
            del self._seen[mid]


class OnionLayer:
    """
    Onion routing for multi-hop sender privacy.
    Each layer wraps the message with a layer of encryption for the next hop.
    The final recipient gets the actual message; intermediate nodes only know
    the previous hop and the next hop.
    """

    @staticmethod
    def wrap_onion(message: dict, route: list, sender_box_key) -> dict:
        """
        Wrap a message in onion layers for the given route.
        route: list of PeerInfo objects (path from sender to recipient)
        Each hop can only unwrap its layer, revealing the next hop.
        """
        if not route:
            return message

        # Build layers from inside out (last hop first)
        current_payload = json.dumps(message).encode("utf-8")

        for peer in reversed(route):
            if not peer.profile_data or "box_public_key" not in peer.profile_data:
                continue

            try:
                peer_pk = nacl.public.PublicKey(
                    peer.profile_data["box_public_key"].encode(),
                    nacl.encoding.Base64Encoder,
                )
                ephemeral = nacl.public.PrivateKey.generate()
                box = nacl.public.Box(ephemeral, peer_pk)
                encrypted = box.encrypt(current_payload)

                layer = {
                    "onion": True,
                    "ephemeral_key": nacl.encoding.Base64Encoder.encode(
                        ephemeral.public_key.encode()
                    ).decode(),
                    "payload": nacl.encoding.Base64Encoder.encode(encrypted).decode(),
                    "next_hop": peer.fingerprint,
                }

                current_payload = json.dumps(layer).encode("utf-8")
            except Exception as e:
                logger.warning("Onion wrap failed for hop %s: %s", peer.fingerprint, e)
                continue

        try:
            return json.loads(current_payload.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return message

    @staticmethod
    def unwrap_onion(layer: dict, private_key) -> Optional[dict]:
        """
        Unwrap one onion layer using our private key.
        Returns the inner payload (which may be another onion layer or the final message).
        """
        try:
            ephemeral_pk = nacl.public.PublicKey(
                layer["ephemeral_key"].encode(),
                nacl.encoding.Base64Encoder,
            )
            encrypted = nacl.encoding.Base64Encoder.decode(
                layer["payload"].encode()
            )

            box = nacl.public.Box(private_key, ephemeral_pk)
            decrypted = box.decrypt(encrypted)

            return json.loads(decrypted.decode("utf-8"))
        except Exception as e:
            logger.debug("Onion unwrap failed: %s", e)
            return None


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
        self.trust_score = 0.5  # 0.0 = untrusted, 1.0 = fully trusted
        self.messages_relayed = 0
        self.failed_connections = 0

    def update_trust(self, success: bool):
        """Update trust score based on interaction outcome."""
        if success:
            self.trust_score = min(1.0, self.trust_score + 0.05)
            self.messages_relayed += 1
        else:
            self.trust_score = max(0.0, self.trust_score - 0.1)
            self.failed_connections += 1

    def __repr__(self):
        return f"Peer({self.fingerprint[:8]}@{self.address}:{self.port} trust={self.trust_score:.2f})"


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
            "capabilities": ["pfs", "onion", "channels", "files", "tor", "receipts"],
        }).encode("utf-8")

        header = MESHBOX_MAGIC + struct.pack("!BI", PROTOCOL_VERSION, len(payload))
        return header + payload

    def _parse_announce_packet(self, data: bytes, addr: str) -> Optional[PeerInfo]:
        if len(data) < 9 or data[:4] != MESHBOX_MAGIC:
            return None

        version = data[4]
        if version < 1:
            return None

        payload_len = struct.unpack("!I", data[5:9])[0]
        if payload_len > 4096:  # Limit discovery packet size
            return None
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
    """TCP transport for message exchange between peers with rate limiting."""

    def __init__(self, local_fingerprint: str, port: int = MESHBOX_PORT):
        self.local_fingerprint = local_fingerprint
        self.port = port
        self.on_message_received: Optional[Callable] = None
        self.on_sync_request: Optional[Callable] = None
        self.on_delivery_receipt: Optional[Callable] = None
        self.on_directory_announce: Optional[Callable] = None
        self.on_directory_query: Optional[Callable] = None
        self.on_peer_gossip: Optional[Callable] = None
        self._server = None
        self.connection_limiter = RateLimiter(MAX_CONNECTIONS_PER_IP, 60)
        self.message_limiter = RateLimiter(MAX_MESSAGES_PER_PEER, 60)
        self.deduplicator = MessageDeduplicator()
        self._bytes_sent = 0
        self._bytes_received = 0

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
        ip = addr[0] if addr else "unknown"

        # Rate limit connections per IP
        if not self.connection_limiter.allow(ip):
            logger.warning("Rate limited: %s", ip)
            writer.close()
            await writer.wait_closed()
            return

        logger.info("Incoming connection from %s", addr)

        try:
            header = await asyncio.wait_for(reader.readexactly(9), timeout=10)
            if header[:4] != MESHBOX_MAGIC:
                writer.close()
                return

            payload_len = struct.unpack("!I", header[5:9])[0]
            if payload_len > MAX_PAYLOAD_SIZE:
                logger.warning("Oversized payload from %s: %d bytes", ip, payload_len)
                writer.close()
                return

            data = await asyncio.wait_for(reader.readexactly(payload_len), timeout=30)
            request = json.loads(data)

            command = request.get("command")

            # Rate limit messages per peer fingerprint
            sender_fp = request.get("sender_fingerprint", ip)
            if not self.message_limiter.allow(sender_fp):
                response = {"status": "error", "message": "Rate limited"}
            else:
                handlers = {
                    "sync": self._handle_sync,
                    "deliver": self._handle_deliver,
                    "profile": self._handle_profile,
                    "file": self._handle_file,
                    "sos": self._handle_sos,
                    "location": self._handle_location,
                    "channel": self._handle_channel,
                    "onion": self._handle_onion,
                    "ping": self._handle_ping,
                    "receipt": self._handle_receipt,
                    "receipt_ack": self._handle_receipt_ack,
                    "directory_announce": self._handle_directory_announce,
                    "directory_query": self._handle_directory_query,
                    "peer_gossip": self._handle_peer_gossip,
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
        msg = request.get("message", {})
        msg_id = msg.get("message_id", "")

        # Deduplicate
        if msg_id and self.deduplicator.is_duplicate(msg_id):
            return {"status": "ok", "duplicate": True}

        # Check hop count
        hop_count = msg.get("hop_count", 0)
        if hop_count > MAX_HOP_COUNT:
            return {"status": "error", "message": "Max hops exceeded"}

        msg["hop_count"] = hop_count + 1

        if self.on_message_received:
            await self.on_message_received(msg)
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

    async def _handle_onion(self, request: dict) -> dict:
        """Handle an onion-routed message - unwrap and forward or deliver."""
        if self.on_message_received:
            await self.on_message_received({"type": "onion", **request})
        return {"status": "ok"}

    async def _handle_ping(self, request: dict) -> dict:
        """Simple ping for peer liveness checking."""
        return {
            "status": "ok",
            "fingerprint": self.local_fingerprint,
            "timestamp": int(time.time()),
            "version": PROTOCOL_VERSION,
        }

    async def _handle_receipt(self, request: dict) -> dict:
        """Handle a delivery receipt from a recipient."""
        if self.on_delivery_receipt:
            await self.on_delivery_receipt(request)
        return {"status": "ok"}

    async def _handle_receipt_ack(self, request: dict) -> dict:
        """Handle acknowledgment that our receipt was received."""
        if self.on_delivery_receipt:
            await self.on_delivery_receipt({"type": "receipt_ack", **request})
        return {"status": "ok"}

    async def _handle_directory_announce(self, request: dict) -> dict:
        """Handle incoming directory announcement."""
        if self.on_directory_announce:
            return await self.on_directory_announce(request)
        return {"status": "error", "message": "Not a directory node"}

    async def _handle_directory_query(self, request: dict) -> dict:
        """Handle incoming directory query."""
        if self.on_directory_query:
            return await self.on_directory_query(request)
        return {"status": "error", "message": "Not a directory node"}

    async def _handle_peer_gossip(self, request: dict) -> dict:
        """Handle incoming peer gossip."""
        if self.on_peer_gossip:
            return await self.on_peer_gossip(request)
        return {"status": "ok"}

    async def send_to_peer(self, peer: PeerInfo, command: str,
                           payload: dict, retries: int = MAX_SEND_RETRIES) -> Optional[dict]:
        """Send a command to a peer with exponential backoff retry."""
        last_error = None
        for attempt in range(retries):
            try:
                result = await self._send_once(peer, command, payload)
                if result is not None:
                    peer.update_trust(True)
                    return result
            except Exception as e:
                last_error = e
                logger.debug("Send attempt %d/%d to %s failed: %s",
                             attempt + 1, retries, peer, e)

            if attempt < retries - 1:
                delay = RETRY_BASE_DELAY * (2 ** attempt)
                await asyncio.sleep(delay)

        logger.error("All %d send attempts to %s failed: %s", retries, peer, last_error)
        peer.update_trust(False)
        return None

    async def _send_once(self, peer: PeerInfo, command: str, payload: dict) -> Optional[dict]:
        """Send a single request to a peer."""
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(peer.address, peer.port),
            timeout=10
        )
        try:
            request = {"command": command, **payload}
            data = json.dumps(request).encode("utf-8")
            header = MESHBOX_MAGIC + struct.pack("!BI", PROTOCOL_VERSION, len(data))

            writer.write(header + data)
            await writer.drain()
            self._bytes_sent += len(header) + len(data)

            # Bandwidth throttle
            if BANDWIDTH_LIMIT > 0:
                await asyncio.sleep(len(data) / BANDWIDTH_LIMIT)

            resp_header = await asyncio.wait_for(reader.readexactly(9), timeout=10)
            resp_len = struct.unpack("!I", resp_header[5:9])[0]
            if resp_len > MAX_PAYLOAD_SIZE:
                return None

            resp_data = await asyncio.wait_for(reader.readexactly(resp_len), timeout=30)
            self._bytes_received += 9 + resp_len

            return json.loads(resp_data)
        finally:
            writer.close()
            await writer.wait_closed()

    def get_bandwidth_stats(self) -> dict:
        return {"bytes_sent": self._bytes_sent, "bytes_received": self._bytes_received}


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
    """Main network manager - coordinates WiFi, Bluetooth and Tor transport."""

    def __init__(self, profile_data: dict):
        self.profile_data = profile_data
        self.wifi_discovery = WiFiDiscovery(profile_data)
        self.bt_discovery = BluetoothDiscovery(profile_data)
        self.transport = MessageTransport(profile_data["fingerprint"])
        self.all_peers: dict[str, PeerInfo] = {}
        self.on_peer_discovered: Optional[Callable] = None
        self.on_message_received: Optional[Callable] = None
        self.on_delivery_receipt: Optional[Callable] = None
        self._tor_transport = None  # Set by daemon when Tor is enabled

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

    def get_peers(self) -> list:
        """Return all discovered peers (WiFi + BLE)."""
        return list(self.all_peers.values())

    def get_peer(self, fingerprint: str) -> Optional[PeerInfo]:
        """Get a specific peer by fingerprint."""
        return self.all_peers.get(fingerprint)

    def get_trusted_peers(self, min_trust: float = 0.3) -> list:
        """Return peers above a trust threshold, sorted by trust score."""
        peers = [p for p in self.all_peers.values() if p.trust_score >= min_trust]
        return sorted(peers, key=lambda p: p.trust_score, reverse=True)

    async def start(self):
        self.wifi_discovery.on_peer_discovered = self._on_wifi_peer
        self.bt_discovery.on_peer_discovered = self._on_bt_peer

        if self.on_message_received:
            self.transport.on_message_received = self.on_message_received
        if self.on_delivery_receipt:
            self.transport.on_delivery_receipt = self.on_delivery_receipt

        tasks = [
            asyncio.create_task(self.wifi_discovery.start_announcer()),
            asyncio.create_task(self.wifi_discovery.start_listener()),
            asyncio.create_task(self.bt_discovery.start_advertising()),
            asyncio.create_task(self.bt_discovery.start_scanner()),
            asyncio.create_task(self.transport.start_server()),
            asyncio.create_task(self._peer_cleanup_loop()),
        ]

        await asyncio.gather(*tasks, return_exceptions=True)

    async def _peer_cleanup_loop(self):
        """Remove stale peers periodically."""
        while True:
            await asyncio.sleep(120)
            now = time.time()
            stale = [
                fp for fp, peer in self.all_peers.items()
                if now - peer.last_seen > PEER_STALE_TIMEOUT
            ]
            for fp in stale:
                del self.all_peers[fp]
                logger.debug("Removed stale peer: %s", fp)

            # Cleanup rate limiters
            self.transport.connection_limiter.cleanup()
            self.transport.message_limiter.cleanup()

    def stop(self):
        self.wifi_discovery.stop()
        self.bt_discovery.stop()

    async def send_to_peer_or_tor(self, fingerprint: str, command: str,
                                   payload: dict) -> Optional[dict]:
        """Try to send via local mesh first, fall back to Tor if available."""
        # Try local mesh peer
        peer = self.get_peer(fingerprint)
        if peer:
            result = await self.transport.send_to_peer(peer, command, payload)
            if result:
                return result

        # Fall back to Tor transport
        if self._tor_transport:
            try:
                return await self._tor_transport.send_to_onion(fingerprint, command, payload)
            except Exception as e:
                logger.debug("Tor send to %s failed: %s", fingerprint, e)

        return None

    def set_tor_transport(self, tor_transport):
        """Set the Tor transport for internet-based P2P."""
        self._tor_transport = tor_transport
