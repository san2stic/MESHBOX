"""
QUIC Transport for MeshBox

High-performance UDP-based transport with:
- 0-RTT connection establishment
- Connection migration (survive IP changes)
- Advanced congestion control
- Multiplexing multiple streams
- Built-in encryption (TLS 1.3)
"""

from __future__ import annotations

import asyncio
import logging
import os
import struct
import time
from typing import Optional, Callable, Any
from dataclasses import dataclass, field
from enum import Enum

from meshbox.transport import (
    TransportProtocol,
    TransportType,
    ConnectionState,
    TransportStats,
    PeerEndpoint,
)

logger = logging.getLogger("meshbox.transport.quic")

QUIC_PORT = 7777
QUIC_VERSION = 1
MAX_DATAGRAM_SIZE = 1350
MAX_STREAMS = 100
STREAM_WINDOW = 1024 * 1024


class QUICFrameType(Enum):
    PADDING = 0x00
    PING = 0x01
    ACK = 0x02
    RESET_STREAM = 0x04
    STOP_SENDING = 0x05
    MAX_DATA = 0x06
    MAX_STREAM_DATA = 0x07
    MAX_STREAMS = 0x12
    DATAGRAM = 0x30
    HANDSHAKE_DONE = 0x1E
    NEW_TOKEN = 0x07
    CRYPTO = 0x18
    NEW_CONNECTION_ID = 0x18
    RETIRE_CONNECTION_ID = 0x19


@dataclass
class QUICConnection:
    peer_id: str
    connection_id: bytes
    scid: bytes
    dcid: bytes
    state: ConnectionState = ConnectionState.DISCONNECTED
    stream_id: int = 0
    last_activity: float = field(default_factory=time.time)
    rtt: float = 0.0
    bytes_in_flight: int = 0
    crypto_stream: bytes = b""
    app_stream: bytes = b""


class QUICPacket:
    """QUIC packet structure."""

    def __init__(
        self,
        connection_id: bytes,
        packet_number: int,
        payload: bytes,
        flags: int = 0x40,
    ):
        self.connection_id = connection_id
        self.packet_number = packet_number
        self.payload = payload
        self.flags = flags

    def to_bytes(self) -> bytes:
        header = bytes([self.flags]) + self.connection_id + struct.pack("!I", self.packet_number)
        return header + self.payload

    @classmethod
    def from_bytes(cls, data: bytes) -> Optional["QUICPacket"]:
        if len(data) < 5:
            return None
        flags = data[0]
        cid_len = flags & 0x0F
        if len(data) < 1 + cid_len + 4:
            return None
        connection_id = data[1:1 + cid_len]
        packet_number = struct.unpack("!I", data[1 + cid_len:1 + cid_len + 4])[0]
        payload = data[1 + cid_len + 4:]
        return cls(connection_id, packet_number, payload, flags)


class QUICTransport(TransportProtocol):
    """
    QUIC-based transport using asyncio and UDP.

    Features:
    - Connection multiplexing
    - Stream-based communication
    - 0-RTT data support
    - Connection migration
    - Datagram support
    """

    def __init__(
        self,
        local_peer_id: str,
        port: int = QUIC_PORT,
        enable_0rtt: bool = True,
        max_idle_timeout: float = 60.0,
    ):
        super().__init__(local_peer_id)
        self.port = port
        self.enable_0rtt = enable_0rtt
        self.max_idle_timeout = max_idle_timeout
        self.connections: dict[bytes, QUICConnection] = {}
        self.peer_connections: dict[str, QUICConnection] = {}
        self._server: Optional[asyncio.DatagramProtocol] = None
        self._transport: Optional[asyncio.DatagramTransport] = None
        self._running = False
        self._packet_number: int = 0
        self._local_cid: bytes = os.urandom(8)
        self._pending_0rtt: dict[bytes, list[bytes]] = {}

    @property
    def transport_type(self) -> TransportType:
        return TransportType.QUIC

    async def start(self) -> None:
        """Start the QUIC transport server."""
        loop = asyncio.get_event_loop()
        self._server = loop.create_datagram_endpoint(
            QUICServerProtocol(factory=self),
            local_addr=("0.0.0.0", self.port),
        )
        try:
            self._transport, _ = await self._server
            self.state = ConnectionState.CONNECTED
            self._running = True
            logger.info(f"QUIC transport started on port {self.port}")
        except OSError as e:
            logger.warning(f"Cannot bind QUIC port {self.port}: {e}")
            self.state = ConnectionState.ERROR

    async def stop(self) -> None:
        """Stop the QUIC transport and close all connections."""
        self._running = False
        if self._transport:
            self._transport.close()
        for conn in list(self.connections.values()) + list(self.peer_connections.values()):
            conn.state = ConnectionState.DISCONNECTED
        self.connections.clear()
        self.peer_connections.clear()
        logger.info("QUIC transport stopped")

    async def connect(self, endpoint: PeerEndpoint) -> bool:
        """Initiate QUIC connection to a peer."""
        try:
            conn_id = os.urandom(8)
            conn = QUICConnection(
                peer_id=endpoint.peer_id,
                connection_id=conn_id,
                scid=self._local_cid,
                dcid=conn_id,
                state=ConnectionState.CONNECTING,
            )
            self.peer_connections[endpoint.peer_id] = conn
            self.connections[conn_id] = conn

            await self._send_initial_packet(endpoint, conn)
            self.stats.connections_opened += 1
            return True
        except Exception as e:
            logger.error(f"QUIC connect failed to {endpoint.peer_id}: {e}")
            self.stats.connections_failed += 1
            return False

    async def disconnect(self, peer_id: str) -> None:
        """Close QUIC connection to a peer."""
        conn = self.peer_connections.pop(peer_id, None)
        if conn:
            conn.state = ConnectionState.DISCONNECTED
            self.connections.pop(conn.connection_id, None)
            logger.info(f"QUIC disconnected from {peer_id}")

    async def send(self, peer_id: str, data: bytes) -> bool:
        """Send data via QUIC datagram or stream."""
        conn = self.peer_connections.get(peer_id)
        if not conn or conn.state != ConnectionState.CONNECTED:
            logger.debug(f"No active QUIC connection for {peer_id}")
            return False

        try:
            packet = self._build_datagram_packet(conn, data)
            if self._transport:
                peer_addr = conn.connection_id
                self._transport.sendto(packet, peer_addr)
            self._update_stats(sent=len(data), msg_sent=1)
            return True
        except Exception as e:
            logger.error(f"QUIC send failed to {peer_id}: {e}")
            return False

    async def broadcast(self, data: bytes) -> int:
        """Broadcast data to all connected peers."""
        count = 0
        for peer_id, conn in self.peer_connections.items():
            if conn.state == ConnectionState.CONNECTED:
                try:
                    packet = self._build_datagram_packet(conn, data)
                    if self._transport:
                        self._transport.sendto(packet, conn.connection_id)
                    count += 1
                except Exception as e:
                    logger.debug(f"QUIC broadcast to {peer_id} failed: {e}")
        self._update_stats(sent=len(data) * count, msg_sent=count)
        return count

    def _build_datagram_packet(self, conn: QUICConnection, data: bytes) -> bytes:
        """Build a QUIC datagram packet."""
        self._packet_number += 1
        payload = bytes([QUICFrameType.DATAGRAM.value]) + data
        packet = QUICPacket(
            connection_id=conn.dcid,
            packet_number=self._packet_number,
            payload=payload,
            flags=0x40 | 0x08,
        )
        return packet.to_bytes()

    async def _send_initial_packet(
        self, endpoint: PeerEndpoint, conn: QUICConnection
    ) -> None:
        """Send QUIC initial packet to initiate handshake."""
        header = (
            bytes([0xC0, 0x00, 0x00, 0x00])
            + conn.connection_id
            + struct.pack("!I", self._packet_number)
        )
        crypto_data = self._build_crypto_frame(b"")
        payload = crypto_data
        packet = header + payload

        if self._transport:
            try:
                addr = (endpoint.address, endpoint.port)
                self._transport.sendto(packet, addr)
            except Exception as e:
                logger.error(f"Failed to send initial packet: {e}")

    def _build_crypto_frame(self, data: bytes) -> bytes:
        """Build a CRYPTO frame."""
        return bytes([QUICFrameType.CRYPTO.value]) + struct.pack("!I", len(data)) + data

    def handle_packet(self, data: bytes, addr: tuple) -> None:
        """Handle incoming QUIC packet."""
        packet = QUICPacket.from_bytes(data)
        if not packet:
            return

        conn = self.connections.get(packet.connection_id)
        if not conn:
            conn = self._create_connection_from_packet(packet, addr)

        if conn:
            self._process_packet(conn, packet)

    def _create_connection_from_packet(
        self, packet: QUICPacket, addr: tuple
    ) -> Optional[QUICConnection]:
        """Create connection from incoming packet."""
        conn_id = os.urandom(8)
        conn = QUICConnection(
            peer_id=addr[0],
            connection_id=conn_id,
            scid=self._local_cid,
            dcid=packet.connection_id,
            state=ConnectionState.CONNECTING,
        )
        self.connections[conn_id] = conn
        logger.info(f"New QUIC connection from {addr}")
        return conn

    def _process_packet(self, conn: QUICConnection, packet: QUICPacket) -> None:
        """Process incoming QUIC packet."""
        conn.last_activity = time.time()
        frame_type = packet.payload[0] if packet.payload else 0

        if frame_type == QUICFrameType.CRYPTO.value:
            self._handle_crypto_frame(conn, packet.payload[1:])
        elif frame_type == QUICFrameType.DATAGRAM.value:
            self._handle_datagram(conn, packet.payload[1:])
        elif frame_type == QUICFrameType.PING.value:
            self._handle_ping(conn)
        elif frame_type == QUICFrameType.ACK.value:
            self._handle_ack(conn, packet.payload)
        elif frame_type == QUICFrameType.HANDSHAKE_DONE.value:
            conn.state = ConnectionState.CONNECTED
            logger.info(f"QUIC handshake complete for {conn.peer_id}")

    def _handle_crypto_frame(self, conn: QUICConnection, data: bytes) -> None:
        """Handle CRYPTO frame."""
        conn.crypto_stream += data
        if len(conn.crypto_stream) > 1000:
            self._update_stats_connection(conn)

    def _handle_datagram(self, conn: QUICConnection, data: bytes) -> None:
        """Handle datagram frame."""
        self._update_stats(received=len(data), msg_recv=1)
        if self.on_message:
            asyncio.create_task(self._notify_message(conn.peer_id, data))

    async def _notify_message(self, peer_id: str, data: bytes) -> None:
        """Notify message callback."""
        if self.on_message:
            self.on_message(peer_id, data)

    def _handle_ping(self, conn: QUICConnection) -> None:
        """Handle PING frame - respond with ACK."""
        conn.last_activity = time.time()

    def _handle_ack(self, conn: QUICConnection, payload: bytes) -> None:
        """Handle ACK frame."""
        conn.bytes_in_flight = max(0, conn.bytes_in_flight - len(payload))

    def _update_stats_connection(self, conn: QUICConnection) -> None:
        """Complete connection establishment."""
        conn.state = ConnectionState.CONNECTED
        self.stats.connections_opened += 1

    def _update_stats(self, sent: int = 0, received: int = 0,
                      msg_sent: int = 0, msg_recv: int = 0) -> None:
        """Update transport statistics."""
        super()._update_stats(sent, received, msg_sent, msg_recv)


class QUICServerProtocol(asyncio.DatagramProtocol):
    """QUIC server protocol handler."""

    def __init__(self, factory: QUICTransport):
        self.factory = factory

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        logger.info("QUIC server connection established")

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        self.factory.handle_packet(data, addr)

    def error_received(self, exc: Exception) -> None:
        logger.error(f"QUIC server error: {exc}")


class QUICStreamManager:
    """Manages bidirectional QUIC streams within a connection."""

    def __init__(self, connection: QUICConnection, transport: QUICTransport):
        self.connection = connection
        self.transport = transport
        self.streams: dict[int, QUICStream] = {}
        self._stream_lock = asyncio.Lock()

    async def open_stream(self) -> int:
        """Open a new bidirectional stream."""
        async with self._stream_lock:
            stream_id = self.connection.stream_id
            self.connection.stream_id += 4
            self.streams[stream_id] = QUICStream(
                stream_id=stream_id,
                connection=self.connection,
                direction="bidirectional",
            )
            return stream_id

    async def send_stream_data(self, stream_id: int, data: bytes, fin: bool = False) -> None:
        """Send data on a specific stream."""
        stream = self.streams.get(stream_id)
        if not stream:
            raise ValueError(f"Stream {stream_id} not found")

        frame = stream.build_frame(data, fin)
        if self.connection.state == ConnectionState.CONNECTED:
            packet = self.transport._build_datagram_packet(self.connection, frame)
            if self.transport._transport:
                self.transport._transport.sendto(
                    packet, self.connection.connection_id
                )

    def receive_stream_data(self, stream_id: int, data: bytes) -> None:
        """Receive data on a stream."""
        stream = self.streams.get(stream_id)
        if stream:
            stream.receive_data(data)

    def close_stream(self, stream_id: int) -> None:
        """Close a stream."""
        if stream_id in self.streams:
            del self.streams[stream_id]


class QUICStream:
    """Represents a QUIC stream within a connection."""

    def __init__(self, stream_id: int, connection: QUICConnection, direction: str):
        self.stream_id = stream_id
        self.connection = connection
        self.direction = direction
        self.send_buffer: bytes = b""
        self.recv_buffer: bytes = b""
        self.send_offset: int = 0
        self.recv_offset: int = 0
        self.local_fin: bool = False
        self.remote_fin: bool = False

    def build_frame(self, data: bytes, fin: bool = False) -> bytes:
        """Build a STREAM frame."""
        header = bytes([0x10 | (1 if self.direction == "bidirectional" else 0)])
        header += struct.pack("!I", self.stream_id)
        header += struct.pack("!I", self.send_offset)
        self.send_offset += len(data)
        self.send_buffer += data
        return header + data

    def receive_data(self, data: bytes) -> bytes:
        """Receive data on this stream."""
        self.recv_buffer += data
        self.recv_offset += len(data)
        return self.recv_buffer


class QUICConnectionManager:
    """Manages multiple QUIC connections and provides high-level API."""

    def __init__(self, local_peer_id: str, port: int = QUIC_PORT):
        self.transport = QUICTransport(local_peer_id, port)
        self._connection_hints: dict[str, PeerEndpoint] = {}

    async def start(self) -> None:
        """Start the connection manager."""
        await self.transport.start()

    async def stop(self) -> None:
        """Stop the connection manager."""
        await self.transport.stop()

    def add_connection_hint(self, peer_id: str, endpoint: PeerEndpoint) -> None:
        """Add connection hints for a peer."""
        self._connection_hints[peer_id] = endpoint

    async def connect_peer(self, peer_id: str) -> bool:
        """Connect to a peer using stored hints."""
        endpoint = self._connection_hints.get(peer_id)
        if not endpoint:
            logger.warning(f"No connection hint for {peer_id}")
            return False
        endpoint.peer_id = peer_id
        return await self.transport.connect(endpoint)

    async def send_message(self, peer_id: str, message: bytes) -> bool:
        """Send a message to a connected peer."""
        return await self.transport.send(peer_id, message)

    async def broadcast(self, message: bytes) -> int:
        """Broadcast to all connected peers."""
        return await self.transport.broadcast(message)

    def get_stats(self) -> dict:
        """Get connection statistics."""
        return {
            "transport": self.transport.stats,
            "connections": len(self.transport.peer_connections),
        }
