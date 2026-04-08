"""
Tests for the Multi-Transport Layer
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from meshbox.transport import (
    TransportProtocol,
    TransportType,
    ConnectionState,
    TransportStats,
    PeerEndpoint,
    MultiTransportManager,
)


class TestTransportStats:
    """Tests for TransportStats dataclass."""

    def test_default_stats(self):
        stats = TransportStats()
        assert stats.bytes_sent == 0
        assert stats.bytes_received == 0
        assert stats.messages_sent == 0
        assert stats.messages_received == 0
        assert stats.connections_opened == 0
        assert stats.connections_failed == 0

    def test_stats_with_values(self):
        stats = TransportStats(
            bytes_sent=1000,
            bytes_received=2000,
            messages_sent=10,
            messages_received=20,
        )
        assert stats.bytes_sent == 1000
        assert stats.messages_received == 20


class TestPeerEndpoint:
    """Tests for PeerEndpoint dataclass."""

    def test_peer_endpoint_creation(self):
        endpoint = PeerEndpoint(
            peer_id="test-peer",
            address="192.168.1.1",
            port=8080,
            transport_type=TransportType.TCP,
        )
        assert endpoint.peer_id == "test-peer"
        assert endpoint.address == "192.168.1.1"
        assert endpoint.port == 8080
        assert endpoint.transport_type == TransportType.TCP
        assert endpoint.public_key is None
        assert endpoint.metadata == {}

    def test_peer_endpoint_with_metadata(self):
        endpoint = PeerEndpoint(
            peer_id="test-peer",
            address="192.168.1.1",
            port=8080,
            transport_type=TransportType.WEBRTC,
            public_key=b"test-key",
            metadata={"rssi": -50},
        )
        assert endpoint.public_key == b"test-key"
        assert endpoint.metadata["rssi"] == -50


class TestTransportProtocol(TransportProtocol):
    """Test implementation of TransportProtocol."""

    @property
    def transport_type(self) -> TransportType:
        return TransportType.TCP

    async def start(self) -> None:
        self.state = ConnectionState.CONNECTED

    async def stop(self) -> None:
        self.state = ConnectionState.DISCONNECTED

    async def connect(self, endpoint: PeerEndpoint) -> bool:
        return True

    async def disconnect(self, peer_id: str) -> None:
        pass

    async def send(self, peer_id: str, data: bytes) -> bool:
        self._update_stats(sent=len(data), msg_sent=1)
        return True

    async def broadcast(self, data: bytes) -> int:
        self._update_stats(sent=len(data), msg_sent=1)
        return 1


class TestTransportProtocolBase:
    """Tests for TransportProtocol base class."""

    @pytest.fixture
    def transport(self):
        return TestTransportProtocol("test-peer-id")

    @pytest.mark.asyncio
    async def test_start(self, transport):
        await transport.start()
        assert transport.state == ConnectionState.CONNECTED

    @pytest.mark.asyncio
    async def test_stop(self, transport):
        await transport.start()
        await transport.stop()
        assert transport.state == ConnectionState.DISCONNECTED

    @pytest.mark.asyncio
    async def test_send_updates_stats(self, transport):
        await transport.start()
        await transport.send("peer-1", b"test message")
        assert transport.stats.bytes_sent == 12
        assert transport.stats.messages_sent == 1

    def test_update_stats(self, transport):
        transport._update_stats(sent=100, received=200, msg_sent=5, msg_recv=10)
        assert transport.stats.bytes_sent == 100
        assert transport.stats.bytes_received == 200
        assert transport.stats.messages_sent == 5
        assert transport.stats.messages_received == 10
        assert transport.stats.last_activity > 0


class TestMultiTransportManager:
    """Tests for MultiTransportManager."""

    @pytest.fixture
    def manager(self):
        return MultiTransportManager("test-local-peer")

    @pytest.fixture
    def mock_transport(self):
        transport = TestTransportProtocol("test-local-peer")
        transport._running = False
        return transport

    def test_manager_creation(self, manager):
        assert manager.local_peer_id == "test-local-peer"
        assert len(manager.transports) == 0
        assert len(manager.active_connections) == 0

    def test_register_transport(self, manager, mock_transport):
        manager.register_transport(mock_transport)
        assert TransportType.TCP in manager.transports
        assert mock_transport.on_connected is not None
        assert mock_transport.on_disconnected is not None
        assert mock_transport.on_message is not None

    @pytest.mark.asyncio
    async def test_start_all(self, manager, mock_transport):
        manager.register_transport(mock_transport)
        await manager.start_all()
        assert mock_transport._running is True

    @pytest.mark.asyncio
    async def test_stop_all(self, manager, mock_transport):
        manager.register_transport(mock_transport)
        await manager.start_all()
        await manager.stop_all()
        assert mock_transport._running is False

    @pytest.mark.asyncio
    async def test_get_transport_stats(self, manager, mock_transport):
        manager.register_transport(mock_transport)
        stats = manager.get_transport_stats()
        assert TransportType.TCP in stats
        assert isinstance(stats[TransportType.TCP], TransportStats)


class TestTransportType:
    """Tests for TransportType enum."""

    def test_all_transport_types_exist(self):
        assert TransportType.WEBRTC is not None
        assert TransportType.QUIC is not None
        assert TransportType.TCP is not None
        assert TransportType.UDP is not None
        assert TransportType.BLUETOOTH_LE is not None
        assert TransportType.TOR is not None
        assert TransportType.LOCAL is not None

    def test_transport_type_values(self):
        assert TransportType.WEBRTC.value == "webrtc"
        assert TransportType.QUIC.value == "quic"
        assert TransportType.BLUETOOTH_LE.value == "bt_le"


class TestConnectionState:
    """Tests for ConnectionState enum."""

    def test_all_states_exist(self):
        assert ConnectionState.DISCONNECTED is not None
        assert ConnectionState.CONNECTING is not None
        assert ConnectionState.CONNECTED is not None
        assert ConnectionState.ERROR is not None

    def test_state_values(self):
        assert ConnectionState.CONNECTED.value == "connected"
        assert ConnectionState.DISCONNECTED.value == "disconnected"
