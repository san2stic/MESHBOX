"""
Tests for WebRTC Transport
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import time

from meshbox.transport.webrtc_transport import (
    WebRTCTransport,
    WebRTCOffer,
    ICEConfiguration,
    DataChannelConfig,
    WebRTCPeerConnection,
    WebRTCSessionManager,
    WebRTCSignalingHub,
)


class TestICEConfiguration:
    """Tests for ICEConfiguration."""

    def test_default_config(self):
        config = ICEConfiguration()
        assert len(config.stun_servers) > 0
        assert config.turn_servers == []
        assert config.ice_candidate_pool_size == 0

    def test_custom_config(self):
        config = ICEConfiguration(
            stun_servers=["stun:custom.server:3478"],
            turn_servers=[{"url": "turn:custom.server:3478", "username": "user", "credential": "pass"}],
            ice_candidate_pool_size=2,
        )
        assert config.stun_servers == ["stun:custom.server:3478"]
        assert len(config.turn_servers) == 1
        assert config.ice_candidate_pool_size == 2

    def test_to_dict(self):
        config = ICEConfiguration()
        result = config.to_dict()
        assert "iceServers" in result
        assert isinstance(result["iceServers"], list)


class TestDataChannelConfig:
    """Tests for DataChannelConfig."""

    def test_default_config(self):
        config = DataChannelConfig()
        assert config.ordered is True
        assert config.max_packet_lifetime == 0
        assert config.max_retransmits == 0
        assert config.protocol == ""
        assert config.negotiated is False


class TestWebRTCOffer:
    """Tests for WebRTCOffer."""

    def test_offer_creation(self):
        offer = WebRTCOffer(sdp="v=0\r\n", type="offer")
        assert offer.sdp == "v=0\r\n"
        assert offer.type == "offer"

    def test_to_json(self):
        offer = WebRTCOffer(sdp="v=0\r\n", type="offer")
        json_data = offer.to_json()
        assert json_data["sdp"] == "v=0\r\n"
        assert json_data["type"] == "offer"

    def test_from_json(self):
        data = {"sdp": "test-sdp", "type": "answer"}
        offer = WebRTCOffer.from_json(data)
        assert offer.sdp == "test-sdp"
        assert offer.type == "answer"


class TestWebRTCPeerConnection:
    """Tests for WebRTCPeerConnection."""

    def test_peer_connection_creation(self):
        pc = WebRTCPeerConnection(
            peer_id="test-peer",
            connection=MagicMock(),
        )
        assert pc.peer_id == "test-peer"
        assert pc.state.value == "disconnected"
        assert pc.last_ping == 0.0
        assert pc.round_trip_time == 0.0


class TestWebRTCTransport:
    """Tests for WebRTCTransport."""

    @pytest.fixture
    def transport(self):
        return WebRTCTransport(
            local_peer_id="test-local-peer",
            signaling_callback=AsyncMock(),
        )

    @pytest.mark.asyncio
    async def test_start(self, transport):
        await transport.start()
        assert transport.state.value == "connected"
        assert transport._running is True

    @pytest.mark.asyncio
    async def test_stop(self, transport):
        await transport.start()
        await transport.stop()
        assert transport.state.value == "disconnected"
        assert transport._running is False

    @pytest.mark.asyncio
    async def test_transport_type(self, transport):
        assert transport.transport_type.value == "webrtc"

    @pytest.mark.asyncio
    async def test_connect(self, transport):
        endpoint = MagicMock()
        endpoint.peer_id = "remote-peer"
        endpoint.address = "192.168.1.1"
        endpoint.port = 8080

        result = await transport.connect(endpoint)
        assert result is True
        assert "remote-peer" in transport.peer_connections

    @pytest.mark.asyncio
    async def test_disconnect(self, transport):
        endpoint = MagicMock()
        endpoint.peer_id = "remote-peer"
        endpoint.address = "192.168.1.1"
        endpoint.port = 8080

        await transport.connect(endpoint)
        await transport.disconnect("remote-peer")
        assert "remote-peer" not in transport.peer_connections

    @pytest.mark.asyncio
    async def test_broadcast(self, transport):
        await transport.start()
        count = await transport.broadcast(b"test message")
        assert count == 0


class TestWebRTCSessionManager:
    """Tests for WebRTCSessionManager."""

    @pytest.fixture
    def manager(self):
        return WebRTCSessionManager("test-local-peer")

    @pytest.mark.asyncio
    async def test_start_stop(self, manager):
        await manager.start()
        await manager.stop()

    @pytest.mark.asyncio
    async def test_session_creation(self, manager):
        await manager.start()
        endpoint = MagicMock()
        endpoint.peer_id = "remote"
        endpoint.address = "192.168.1.1"
        endpoint.port = 8080
        endpoint.transport_type.value = "webrtc"

        with patch.object(manager.transport, 'connect', new_callable=AsyncMock) as mock_connect:
            mock_connect.return_value = True
            result = await manager.create_session("remote", endpoint)
            assert result is True

    @pytest.mark.asyncio
    async def test_get_all_sessions(self, manager):
        await manager.start()
        sessions = manager.get_all_sessions()
        assert isinstance(sessions, list)


class TestWebRTCSignalingHub:
    """Tests for WebRTCSignalingHub."""

    @pytest.fixture
    def hub(self):
        transport = WebRTCTransport("test-peer", signaling_callback=AsyncMock())
        return WebRTCSignalingHub(transport)

    @pytest.mark.asyncio
    async def test_start_stop(self, hub):
        await hub.start()
        await hub.stop()
        assert hub._running is False
