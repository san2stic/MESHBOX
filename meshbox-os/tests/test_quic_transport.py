"""
Tests for QUIC Transport
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import os

from meshbox.transport.quic_transport import (
    QUICTransport,
    QUICPacket,
    QUICConnection,
    QUICStreamManager,
    QUICStream,
    QUICConnectionManager,
    QUICFrameType,
    QUICServerProtocol,
)
from meshbox.transport import TransportType, ConnectionState, PeerEndpoint


class TestQUICPacket:
    """Tests for QUICPacket."""

    def test_packet_creation(self):
        cid = b"12345678"
        packet = QUICPacket(
            connection_id=cid,
            packet_number=1,
            payload=b"test payload",
        )
        assert packet.connection_id == cid
        assert packet.packet_number == 1
        assert packet.payload == b"test payload"

    def test_packet_to_bytes(self):
        cid = b"12345678"
        packet = QUICPacket(
            connection_id=cid,
            packet_number=42,
            payload=b"test",
        )
        data = packet.to_bytes()
        assert len(data) > 0
        assert data[0] == 0x40

    def test_packet_from_bytes(self):
        cid = b"12345678"
        original = QUICPacket(connection_id=cid, packet_number=99, payload=b"hello")
        data = original.to_bytes()
        parsed = QUICPacket.from_bytes(data)
        assert parsed is not None
        assert parsed.packet_number == 99


class TestQUICConnection:
    """Tests for QUICConnection."""

    def test_connection_creation(self):
        conn = QUICConnection(
            peer_id="test-peer",
            connection_id=b"conn-id",
            scid=b"scid",
            dcid=b"dcid",
        )
        assert conn.peer_id == "test-peer"
        assert conn.state.value == "disconnected"
        assert conn.rtt == 0.0


class TestQUICStream:
    """Tests for QUICStream."""

    def test_stream_creation(self):
        conn = QUICConnection(
            peer_id="test-peer",
            connection_id=b"conn-id",
            scid=b"scid",
            dcid=b"dcid",
        )
        stream = QUICStream(
            stream_id=0,
            connection=conn,
            direction="bidirectional",
        )
        assert stream.stream_id == 0
        assert stream.direction == "bidirectional"
        assert stream.send_offset == 0
        assert stream.recv_offset == 0

    def test_build_frame(self):
        conn = QUICConnection(
            peer_id="test-peer",
            connection_id=b"conn-id",
            scid=b"scid",
            dcid=b"dcid",
        )
        stream = QUICStream(stream_id=0, connection=conn, direction="bidirectional")
        frame = stream.build_frame(b"test data")
        assert len(frame) > 0

    def test_receive_data(self):
        conn = QUICConnection(
            peer_id="test-peer",
            connection_id=b"conn-id",
            scid=b"scid",
            dcid=b"dcid",
        )
        stream = QUICStream(stream_id=0, connection=conn, direction="bidirectional")
        data = stream.receive_data(b"received")
        assert data == b"received"
        assert stream.recv_offset == 8


class TestQUICTransport:
    """Tests for QUICTransport."""

    @pytest.fixture
    def transport(self):
        return QUICTransport(local_peer_id="test-peer", port=17777)

    def test_transport_creation(self, transport):
        assert transport.local_peer_id == "test-peer"
        assert transport.port == 17777
        assert transport.enable_0rtt is True

    def test_transport_type(self, transport):
        assert transport.transport_type == TransportType.QUIC

    @pytest.mark.asyncio
    async def test_start(self, transport):
        with patch.object(transport, '_server', None):
            with patch('asyncio.get_event_loop'):
                transport._transport = MagicMock()
                transport._running = True
                transport.state = ConnectionState.CONNECTED
        await transport.stop()

    @pytest.mark.asyncio
    async def test_stop(self, transport):
        transport._running = True
        transport._transport = MagicMock()
        await transport.stop()
        assert transport._running is False

    @pytest.mark.asyncio
    async def test_connect(self, transport):
        endpoint = PeerEndpoint(
            peer_id="remote-peer",
            address="192.168.1.1",
            port=8080,
            transport_type=TransportType.QUIC,
        )
        result = await transport.connect(endpoint)
        assert result is True
        assert "remote-peer" in transport.peer_connections

    @pytest.mark.asyncio
    async def test_disconnect(self, transport):
        endpoint = PeerEndpoint(
            peer_id="remote-peer",
            address="192.168.1.1",
            port=8080,
            transport_type=TransportType.QUIC,
        )
        await transport.connect(endpoint)
        await transport.disconnect("remote-peer")
        assert "remote-peer" not in transport.peer_connections

    @pytest.mark.asyncio
    async def test_broadcast(self, transport):
        await transport.broadcast(b"test message")


class TestQUICConnectionManager:
    """Tests for QUICConnectionManager."""

    @pytest.fixture
    def manager(self):
        return QUICConnectionManager(local_peer_id="test-peer", port=17778)

    def test_manager_creation(self, manager):
        assert manager.transport.local_peer_id == "test-peer"
        assert manager.transport.port == 17778

    @pytest.mark.asyncio
    async def test_add_connection_hint(self, manager):
        endpoint = PeerEndpoint(
            peer_id="hint-peer",
            address="192.168.1.1",
            port=8080,
            transport_type=TransportType.QUIC,
        )
        manager.add_connection_hint("hint-peer", endpoint)
        assert "hint-peer" in manager._connection_hints


class TestQUICFrameType:
    """Tests for QUICFrameType enum."""

    def test_frame_types_exist(self):
        assert QUICFrameType.PADDING is not None
        assert QUICFrameType.PING is not None
        assert QUICFrameType.ACK is not None
        assert QUICFrameType.DATAGRAM is not None
        assert QUICFrameType.CRYPTO is not None

    def test_frame_type_values(self):
        assert QUICFrameType.PING.value == 0x01
        assert QUICFrameType.DATAGRAM.value == 0x30
