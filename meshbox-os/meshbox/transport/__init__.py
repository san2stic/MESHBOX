"""
MeshBox Multi-Transport Layer

Provides abstraction for multiple network transports:
- WebRTC: Browser-native P2P with DataChannels
- QUIC: High-performance UDP-based transport with 0-RTT
- TCP/UDP: Direct connections with NAT traversal
- Bluetooth LE: Offline mesh networking
- Tor: Anonymous routing

Each transport implements the TransportProtocol interface.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional
import asyncio
import logging

logger = logging.getLogger("meshbox.transport")


class TransportType(Enum):
    WEBRTC = "webrtc"
    QUIC = "quic"
    TCP = "tcp"
    UDP = "udp"
    BLUETOOTH_LE = "bt_le"
    TOR = "tor"
    LOCAL = "local"


class ConnectionState(Enum):
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    ERROR = "error"


@dataclass
class TransportStats:
    bytes_sent: int = 0
    bytes_received: int = 0
    messages_sent: int = 0
    messages_received: int = 0
    connections_opened: int = 0
    connections_failed: int = 0
    last_activity: float = 0.0


@dataclass
class PeerEndpoint:
    peer_id: str
    address: str
    port: int
    transport_type: TransportType
    public_key: Optional[bytes] = None
    metadata: dict = field(default_factory=dict)


class TransportProtocol(ABC):
    """Abstract base class for all transport implementations."""

    def __init__(self, local_peer_id: str):
        self.local_peer_id = local_peer_id
        self.state = ConnectionState.DISCONNECTED
        self.stats = TransportStats()
        self.on_connected: Optional[Callable[[PeerEndpoint], None]] = None
        self.on_disconnected: Optional[Callable[[str], None]] = None
        self.on_message: Optional[Callable[[str, bytes], None]] = None
        self.on_error: Optional[Callable[[str, Exception], None]] = None

    @property
    @abstractmethod
    def transport_type(self) -> TransportType:
        """Return the type of this transport."""
        pass

    @abstractmethod
    async def start(self) -> None:
        """Start the transport listener."""
        pass

    @abstractmethod
    async def stop(self) -> None:
        """Stop the transport and close all connections."""
        pass

    @abstractmethod
    async def connect(self, endpoint: PeerEndpoint) -> bool:
        """Connect to a remote peer."""
        pass

    @abstractmethod
    async def disconnect(self, peer_id: str) -> None:
        """Disconnect from a peer."""
        pass

    @abstractmethod
    async def send(self, peer_id: str, data: bytes) -> bool:
        """Send data to a connected peer."""
        pass

    @abstractmethod
    async def broadcast(self, data: bytes) -> int:
        """Broadcast data to all connected peers. Returns number of recipients."""
        pass

    def _update_stats(self, sent: int = 0, received: int = 0,
                      msg_sent: int = 0, msg_recv: int = 0):
        """Update transport statistics."""
        import time
        self.stats.bytes_sent += sent
        self.stats.bytes_received += received
        self.stats.messages_sent += msg_sent
        self.stats.messages_received += msg_recv
        self.stats.last_activity = time.time()


class MultiTransportManager:
    """
    Manages multiple transport protocols and provides unified interface.
    Handles transport selection, failover, and health monitoring.
    """

    def __init__(self, local_peer_id: str):
        self.local_peer_id = local_peer_id
        self.transports: dict[TransportType, TransportProtocol] = {}
        self.active_connections: dict[str, tuple[PeerEndpoint, TransportType]] = {}
        self.on_message: Optional[Callable[[str, bytes, TransportType], None]] = None
        self._running = False
        self._lock = asyncio.Lock()

    def register_transport(self, transport: TransportProtocol) -> None:
        """Register a transport protocol."""
        self.transports[transport.transport_type] = transport
        transport.on_connected = self._handle_connected
        transport.on_disconnected = self._handle_disconnected
        transport.on_message = self._handle_message
        transport.on_error = self._handle_error
        logger.info(f"Registered transport: {transport.transport_type.value}")

    async def start_all(self) -> None:
        """Start all registered transports."""
        self._running = True
        tasks = []
        for transport in self.transports.values():
            try:
                await transport.start()
                tasks.append(asyncio.create_task(self._monitor_transport(transport)))
            except Exception as e:
                logger.error(f"Failed to start {transport.transport_type.value}: {e}")
        logger.info(f"Started {len(tasks)} transports")

    async def stop_all(self) -> None:
        """Stop all transports gracefully."""
        self._running = False
        for transport in self.transports.values():
            try:
                await transport.stop()
            except Exception as e:
                logger.error(f"Error stopping {transport.transport_type.value}: {e}")
        self.active_connections.clear()
        logger.info("All transports stopped")

    async def connect_peer(self, endpoint: PeerEndpoint) -> bool:
        """Connect to a peer using the best available transport."""
        transport = self.transports.get(endpoint.transport_type)
        if not transport:
            logger.warning(f"No transport for {endpoint.transport_type.value}")
            return False

        success = await transport.connect(endpoint)
        if success:
            async with self._lock:
                self.active_connections[endpoint.peer_id] = (endpoint, endpoint.transport_type)
        return success

    async def send_to_peer(self, peer_id: str, data: bytes) -> bool:
        """Send data to a connected peer using the appropriate transport."""
        async with self._lock:
            conn = self.active_connections.get(peer_id)

        if not conn:
            return False

        endpoint, transport_type = conn
        transport = self.transports.get(transport_type)
        if not transport:
            return False

        return await transport.send(peer_id, data)

    async def broadcast_all(self, data: bytes) -> dict[TransportType, int]:
        """Broadcast data on all transports. Returns counts per transport."""
        results = {}
        for transport_type, transport in self.transports.items():
            try:
                count = await transport.broadcast(data)
                results[transport_type] = count
            except Exception as e:
                logger.error(f"Broadcast failed on {transport_type.value}: {e}")
                results[transport_type] = 0
        return results

    def get_connected_peers(self) -> list[PeerEndpoint]:
        """Get list of all connected peer endpoints."""
        return [ep for ep, _ in self.active_connections.values()]

    def get_transport_stats(self) -> dict[TransportType, TransportStats]:
        """Get statistics for all transports."""
        return {t: t_obj.stats for t, t_obj in self.transports.items()}

    def _handle_connected(self, endpoint: PeerEndpoint) -> None:
        logger.info(f"Peer connected: {endpoint.peer_id} via {endpoint.transport_type.value}")

    def _handle_disconnected(self, peer_id: str) -> None:
        logger.info(f"Peer disconnected: {peer_id}")
        asyncio.create_task(self._remove_connection(peer_id))

    def _handle_message(self, peer_id: str, data: bytes) -> None:
        if self.on_message:
            transport = self.active_connections.get(peer_id)
            transport_type = transport[1] if transport else TransportType.TCP
            self.on_message(peer_id, data, transport_type)

    def _handle_error(self, peer_id: str, error: Exception) -> None:
        logger.error(f"Transport error for {peer_id}: {error}")

    async def _remove_connection(self, peer_id: str) -> None:
        async with self._lock:
            if peer_id in self.active_connections:
                del self.active_connections[peer_id]

    async def _monitor_transport(self, transport: TransportProtocol) -> None:
        """Monitor transport health."""
        while self._running:
            await asyncio.sleep(30)
            logger.debug(f"{transport.transport_type.value} stats: {transport.stats}")
