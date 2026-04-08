"""
NAT Traversal Module for MeshBox

Provides comprehensive NAT traversal capabilities:
- NAT type classification
- STUN/TURN server integration
- Hole punching coordination
- Port prediction for symmetric NATs
- UPnP/NAT-PMP support
"""

from __future__ import annotations

import asyncio
import logging
import random
import socket
import struct
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Callable

logger = logging.getLogger("meshbox.nat")

STUN_SERVERS = [
    ("stun.l.google.com", 19302),
    ("stun1.l.google.com", 19302),
    ("stun2.l.google.com", 19302),
    ("stun3.l.google.com", 19302),
    ("stun4.l.google.com", 19302),
]

STUN_PORT = 3478
MAX_STUN_RETRIES = 3
STUN_TIMEOUT = 5.0


class NATType(Enum):
    UNKNOWN = "unknown"
    OPEN = "open"
    FULL_CONE = "full_cone"
    RESTRICTED_CONE = "restricted_cone"
    PORT_RESTRICTED_CONE = "port_restricted"
    SYMMETRIC = "symmetric"
    BLOCKED = "blocked"


@dataclass
class NATEndpoint:
    address: str
    port: int
    nat_type: NATType = NATType.UNKNOWN
    mapping_lifetime: float = 0.0


@dataclass
class STUNResponse:
    source_address: str
    source_port: int
    mapped_address: str
    mapped_port: int
    changed_address: Optional[str] = None
    changed_port: Optional[int] = None


class STUNMessage:
    """STUN protocol message structures."""

    BINDING_REQUEST = 0x0001
    BINDING_RESPONSE = 0x0101
    BINDING_ERROR = 0x0111
    CHANGE_REQUEST = 0x0003

    MAPPED_ADDRESS = 0x0001
    RESPONSE_ADDRESS = 0x0002
    CHANGE_REQUEST_ATTR = 0x0003
    SOURCE_ADDRESS = 0x0004
    CHANGED_ADDRESS = 0x0005
    XOR_MAPPED_ADDRESS = 0x0020

    def __init__(self):
        self.transaction_id = bytes(random.randint(0, 255) for _ in range(12))
        self.message_type = self.BINDING_REQUEST
        self.attributes: list[tuple[int, bytes]] = []

    def to_bytes(self) -> bytes:
        payload = b""
        for attr_type, attr_value in self.attributes:
            length = len(attr_value)
            attr_header = struct.pack("!HH", attr_type, length)
            payload += attr_header + attr_value

        message = struct.pack("!HH", self.message_type, len(payload))
        message += self.transaction_id
        message += payload
        return message

    @classmethod
    def from_bytes(cls, data: bytes) -> Optional["STUNMessage"]:
        if len(data) < 20:
            return None

        try:
            msg_type, length = struct.unpack("!HH", data[:4])
            transaction_id = data[4:20]
            payload = data[20:]

            msg = cls()
            msg.message_type = msg_type
            msg.transaction_id = transaction_id

            pos = 0
            while pos < len(payload):
                if pos + 4 > len(payload):
                    break
                attr_type, attr_length = struct.unpack("!HH", payload[pos:pos + 4])
                attr_value = payload[pos + 4:pos + 4 + attr_length]
                msg.attributes.append((attr_type, attr_value))
                pos += 4 + attr_length

            return msg
        except Exception as e:
            logger.debug(f"STUN parse error: {e}")
            return None


class STUNClient:
    """STUN client for NAT type discovery."""

    def __init__(self, server: tuple[str, int] = None):
        self.server = server or STUN_SERVERS[0]
        self._sock: Optional[socket.socket] = None

    async def send_binding_request(
        self,
        change_ip: bool = False,
        change_port: bool = True,
    ) -> Optional[STUNResponse]:
        """Send a STUN binding request."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(STUN_TIMEOUT)

        try:
            sock.bind(("", 0))
            local_port = sock.getsockname()[1]

            request = STUNMessage()
            if change_ip or change_port:
                request.attributes.append(
                    (STUNMessage.CHANGE_REQUEST, struct.pack("!I", (1 if change_ip else 0) | (2 if change_port else 0)))
                )

            sock.sendto(request.to_bytes(), self.server)
            data, addr = sock.recvfrom(1024)

            response = STUNMessage.from_bytes(data)
            if not response or response.message_type != STUNMessage.BINDING_RESPONSE:
                return None

            mapped_addr, mapped_port = self._parse_xor_address(response)
            source_addr, source_port = self._parse_address(response, STUNMessage.SOURCE_ADDRESS)
            changed_addr, changed_port = self._parse_address(response, STUNMessage.CHANGED_ADDRESS)

            return STUNResponse(
                source_address=source_addr or self.server[0],
                source_port=source_port or local_port,
                mapped_address=mapped_addr or "",
                mapped_port=mapped_port or 0,
                changed_address=changed_addr,
                changed_port=changed_port,
            )
        except Exception as e:
            logger.debug(f"STUN request failed: {e}")
            return None
        finally:
            sock.close()

    def _parse_xor_address(self, msg: STUNMessage) -> tuple[Optional[str], Optional[int]]:
        """Parse XOR-MAPPED-ADDRESS attribute."""
        for attr_type, attr_value in msg.attributes:
            if attr_type == STUNMessage.XOR_MAPPED_ADDRESS and len(attr_value) >= 8:
                port = struct.unpack("!H", bytes([attr_value[2] ^ 0x21, attr_value[3] ^ 0x00]))[0]
                addr = ".".join(str(b ^ (0x21 if i == 0 else 0)) for i, b in enumerate(attr_value[4:8]))
                return addr, port
        return None, None

    def _parse_address(self, msg: STUNMessage, attr_type: int) -> tuple[Optional[str], Optional[int]]:
        """Parse MAPPED-ADDRESS or SOURCE-ADDRESS attribute."""
        for atype, avalue in msg.attributes:
            if atype == attr_type and len(avalue) >= 8:
                port = struct.unpack("!H", avalue[2:4])[0]
                addr = ".".join(str(b) for b in avalue[4:8])
                return addr, port
        return None, None


class NATClassifier:
    """Classifies NAT type using STUN tests."""

    def __init__(self, stun_servers: list[tuple[str, int]] = None):
        self.stun_servers = stun_servers or STUN_SERVERS
        self._classifier: Optional[STUNClient] = None

    async def classify(self) -> NATType:
        """Perform NAT classification tests."""
        for server in self.stun_servers:
            self._classifier = STUNClient(server)
            result = await self._run_tests()
            if result:
                return result
        return NATType.UNKNOWN

    async def _run_tests(self) -> Optional[NATType]:
        """Run the STUN test sequence for NAT classification."""
        external = await self._classifier.send_binding_request()
        if not external:
            return NATType.UNKNOWN

        if external.mapped_address == external.source_address:
            if external.changed_address:
                test2 = await self._classifier.send_binding_request(change_port=False)
                if test2 and test2.mapped_port == external.mapped_port:
                    return NATType.OPEN
                return NATType.FULL_CONE

            test3 = await self._classifier.send_binding_request(change_ip=True, change_port=True)
            if not test3 or test3.mapped_address != external.mapped_address:
                return NATType.SYMMETRIC
            return NATType.OPEN

        test4 = await self._classifier.send_binding_request(change_ip=True, change_port=True)
        if test4 and test4.mapped_address == external.mapped_address:
            return NATType.FULL_CONE

        test5 = await self._classifier.send_binding_request(change_ip=False, change_port=True)
        if test5 and test5.mapped_address == external.mapped_address:
            return NATType.RESTRICTED_CONE

        test6 = await self._classifier.send_binding_request(change_ip=False, change_port=False)
        if test6 and test6.mapped_address == external.mapped_address:
            return NATType.PORT_RESTRICTED_CONE

        return NATType.SYMMETRIC

    def get_external_endpoint(self) -> Optional[NATEndpoint]:
        """Get external endpoint information."""
        if not self._classifier:
            return None
        return NATEndpoint(
            address="",
            port=0,
            nat_type=NATType.UNKNOWN,
        )


class HolePuncher:
    """Coordinates UDP hole punching for NAT traversal."""

    def __init__(
        self,
        dht_callback: Callable[[str, dict], None] = None,
        signaling_callback: Callable[[str, dict], None] = None,
    ):
        self.dht_callback = dht_callback
        self.signaling_callback = signaling_callback
        self._pending_sessions: dict[str, asyncio.Future] = {}
        self._punch_attempts: dict[str, int] = {}

    async def initiate_hole_punch(
        self,
        peer_id: str,
        peer_info: dict,
        timeout: float = 30.0,
    ) -> Optional[NATEndpoint]:
        """Initiate hole punching with a peer."""
        future = asyncio.get_event_loop().create_future()
        self._pending_sessions[peer_id] = future

        if self.dht_callback:
            await self.dht_callback("hole_punch_request", {
                "peer_id": peer_id,
                "peer_info": peer_info,
            })

        try:
            result = await asyncio.wait_for(future, timeout=timeout)
            return result
        except asyncio.TimeoutError:
            logger.warning(f"Hole punch timeout for {peer_id}")
            return None
        finally:
            self._pending_sessions.pop(peer_id, None)

    async def handle_hole_punch_response(self, peer_id: str, endpoint: NATEndpoint) -> None:
        """Handle hole punch response from DHT/peer."""
        future = self._pending_sessions.get(peer_id)
        if future and not future.done():
            future.set_result(endpoint)

    def record_punch_attempt(self, peer_id: str) -> None:
        """Record a punch attempt for rate limiting."""
        self._punch_attempts[peer_id] = self._punch_attempts.get(peer_id, 0) + 1

    def get_punch_attempts(self, peer_id: str) -> int:
        """Get number of punch attempts for a peer."""
        return self._punch_attempts.get(peer_id, 0)


class PortPredictor:
    """Predicts external port mappings for symmetric NATs."""

    def __init__(self):
        self._port_mappings: list[tuple[int, int]] = []

    def add_mapping(self, internal_port: int, external_port: int) -> None:
        """Add a port mapping observation."""
        self._port_mappings.append((internal_port, external_port))
        if len(self._port_mappings) > 100:
            self._port_mappings.pop(0)

    def predict_next_port(self, last_internal_port: int) -> Optional[int]:
        """Predict the next external port based on observed patterns."""
        if len(self._port_mappings) < 5:
            return None

        deltas = []
        for i in range(1, len(self._port_mappings)):
            int_delta = self._port_mappings[i][0] - self._port_mappings[i - 1][0]
            ext_delta = self._port_mappings[i][1] - self._port_mappings[i - 1][1]
            deltas.append((int_delta, ext_delta))

        if not deltas:
            return None

        most_common_delta = self._most_common(deltas)
        if most_common_delta:
            return last_internal_port + most_common_delta[1]
        return None

    def _most_common(self, items: list[tuple[int, int]]) -> Optional[tuple[int, int]]:
        """Find the most common item."""
        if not items:
            return None
        counts: dict[tuple[int, int], int] = {}
        for item in items:
            counts[item] = counts.get(item, 0) + 1
        return max(counts.items(), key=lambda x: x[1])[0]


class UPNPManager:
    """Manages UPnP/NAT-PMP port mappings."""

    def __init__(self):
        self._mappings: dict[int, dict] = {}
        self._enabled = False

    async def discover(self) -> bool:
        """Discover UPnP/NAT-PMP on the local network."""
        try:
            import miniupnpc
            u = miniupnpc.UPnP()
            u.discoverdelay = 2000
            devices = u.discover()
            if devices > 0:
                u.selectigd()
                self._enabled = True
                logger.info(f"UPnP discovered: {u.externalipaddress()}")
                return True
        except ImportError:
            logger.debug("miniupnpc not installed")
        except Exception as e:
            logger.warning(f"UPnP discovery failed: {e}")
        return False

    async def add_port_mapping(
        self,
        internal_port: int,
        external_port: int,
        protocol: str = "UDP",
        description: str = "MeshBox",
    ) -> bool:
        """Add a port mapping via UPnP."""
        if not self._enabled:
            await self.discover()
            if not self._enabled:
                return False

        try:
            import miniupnpc
            u = miniupnpc.UPnP()
            u.discoverdelay = 2000
            u.selectigd()
            result = u.addportmapping(
                external_port,
                protocol,
                "0.0.0.0",
                internal_port,
                description,
                "",
            )
            if result:
                self._mappings[internal_port] = {
                    "external_port": external_port,
                    "protocol": protocol,
                }
                logger.info(f"UPnP mapping added: {external_port} -> {internal_port}")
                return True
        except Exception as e:
            logger.error(f"UPnP port mapping failed: {e}")
        return False

    async def remove_port_mapping(self, internal_port: int) -> bool:
        """Remove a port mapping."""
        mapping = self._mappings.get(internal_port)
        if not mapping:
            return False

        try:
            import miniupnpc
            u = miniupnpc.UPnP()
            u.discoverdelay = 2000
            u.selectigd()
            result = u.deleteportmapping(
                mapping["external_port"],
                mapping["protocol"],
            )
            if result:
                del self._mappings[internal_port]
                logger.info(f"UPnP mapping removed: {internal_port}")
                return True
        except Exception as e:
            logger.error(f"UPnP delete mapping failed: {e}")
        return False

    async def cleanup_all(self) -> None:
        """Remove all port mappings."""
        for internal_port in list(self._mappings.keys()):
            await self.remove_port_mapping(internal_port)

    def get_mappings(self) -> dict:
        """Get all active port mappings."""
        return self._mappings.copy()


class NATTraversalEngine:
    """
    Complete NAT traversal engine that coordinates all techniques.
    """

    def __init__(
        self,
        local_peer_id: str,
        internal_port: int,
        external_port: Optional[int] = None,
    ):
        self.local_peer_id = local_peer_id
        self.internal_port = internal_port
        self.external_port = external_port or internal_port

        self.classifier = NATClassifier()
        self.hole_puncher = HolePuncher()
        self.port_predictor = PortPredictor()
        self.upnp = UPNPManager()

        self.nat_type: NATType = NATType.UNKNOWN
        self.external_endpoint: Optional[NATEndpoint] = None
        self._running = False

    async def start(self) -> NATEndpoint:
        """Start NAT traversal and return external endpoint."""
        self._running = True
        logger.info("Starting NAT traversal...")

        self.nat_type = await self.classifier.classify()
        logger.info(f"NAT type detected: {self.nat_type.value}")

        if self.nat_type == NATType.OPEN:
            self.external_endpoint = NATEndpoint(
                address="0.0.0.0",
                port=self.external_port,
                nat_type=self.nat_type,
            )
            return self.external_endpoint

        await self.upnp.discover()
        if self.upnp._enabled:
            await self.upnp.add_port_mapping(
                self.internal_port,
                self.external_port,
                description=f"MeshBox-{self.local_peer_id[:8]}",
            )

        response = await self._classifier_external_endpoint()
        if response:
            self.external_endpoint = NATEndpoint(
                address=response.mapped_address,
                port=response.mapped_port,
                nat_type=self.nat_type,
            )
            self.port_predictor.add_mapping(self.internal_port, response.mapped_port)
            return self.external_endpoint

        return NATEndpoint(
            address="",
            port=0,
            nat_type=self.nat_type,
        )

    async def _classifier_external_endpoint(self) -> Optional[STUNResponse]:
        """Get external endpoint via STUN."""
        for server in STUN_SERVERS:
            try:
                client = STUNClient(server)
                result = await client.send_binding_request()
                if result:
                    return result
            except Exception as e:
                logger.debug(f"STUN server {server} failed: {e}")
        return None

    async def stop(self) -> None:
        """Stop NAT traversal and cleanup."""
        self._running = False
        await self.upnp.cleanup_all()
        logger.info("NAT traversal stopped")

    def get_recommended_strategy(self) -> dict:
        """Get recommended traversal strategy based on NAT type."""
        strategies = {
            NATType.OPEN: {
                "method": "direct",
                "description": "No NAT - direct connection possible",
                "fallback": None,
            },
            NATType.FULL_CONE: {
                "method": "direct",
                "description": "Full cone NAT - direct UDP possible",
                "fallback": "stun",
            },
            NATType.RESTRICTED_CONE: {
                "method": "stun",
                "description": "Restricted cone - STUN with binding",
                "fallback": "hole_punch",
            },
            NATType.PORT_RESTRICTED_CONE: {
                "method": "stun_hole_punch",
                "description": "Port restricted - hole punch required",
                "fallback": "turn",
            },
            NATType.SYMMETRIC: {
                "method": "hole_punch",
                "description": "Symmetric NAT - port prediction + hole punch",
                "fallback": "turn",
            },
            NATType.UNKNOWN: {
                "method": "turn",
                "description": "Unknown NAT - use TURN relay",
                "fallback": None,
            },
        }
        return strategies.get(self.nat_type, strategies[NATType.UNKNOWN])
