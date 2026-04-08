"""
Tests for NAT Traversal Module
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import struct

from meshbox.nat.traversal import (
    NATType,
    NATEndpoint,
    NATClassifier,
    STUNClient,
    STUNMessage,
    STUNResponse,
    HolePuncher,
    PortPredictor,
    UPNPManager,
    NATTraversalEngine,
)


class TestNATType:
    """Tests for NATType enum."""

    def test_all_nat_types_exist(self):
        assert NATType.UNKNOWN is not None
        assert NATType.OPEN is not None
        assert NATType.FULL_CONE is not None
        assert NATType.RESTRICTED_CONE is not None
        assert NATType.PORT_RESTRICTED_CONE is not None
        assert NATType.SYMMETRIC is not None
        assert NATType.BLOCKED is not None

    def test_nat_type_values(self):
        assert NATType.OPEN.value == "open"
        assert NATType.SYMMETRIC.value == "symmetric"


class TestNATEndpoint:
    """Tests for NATEndpoint dataclass."""

    def test_endpoint_creation(self):
        endpoint = NATEndpoint(
            address="192.168.1.1",
            port=8080,
            nat_type=NATType.OPEN,
        )
        assert endpoint.address == "192.168.1.1"
        assert endpoint.port == 8080
        assert endpoint.nat_type == NATType.OPEN


class TestSTUNMessage:
    """Tests for STUNMessage."""

    def test_message_creation(self):
        msg = STUNMessage()
        assert msg.message_type == STUNMessage.BINDING_REQUEST
        assert len(msg.transaction_id) == 12
        assert msg.attributes == []

    def test_message_with_attributes(self):
        msg = STUNMessage()
        msg.attributes.append((STUNMessage.MAPPED_ADDRESS, b"\x00\x01\x00\x00"))
        assert len(msg.attributes) == 1

    def test_message_to_bytes(self):
        msg = STUNMessage()
        msg.attributes.append((STUNMessage.CHANGE_REQUEST, b"\x00\x00\x00\x03"))
        data = msg.to_bytes()
        assert len(data) > 20

    def test_message_from_bytes(self):
        original = STUNMessage()
        original.attributes.append((STUNMessage.MAPPED_ADDRESS, b"\x00" * 8))
        data = original.to_bytes()
        parsed = STUNMessage.from_bytes(data)
        assert parsed is not None
        assert parsed.message_type == STUNMessage.BINDING_REQUEST

    def test_message_from_bytes_invalid(self):
        result = STUNMessage.from_bytes(b"too short")
        assert result is None


class TestSTUNResponse:
    """Tests for STUNResponse dataclass."""

    def test_response_creation(self):
        response = STUNResponse(
            source_address="8.8.8.8",
            source_port=19302,
            mapped_address="192.168.1.1",
            mapped_port=8080,
        )
        assert response.source_address == "8.8.8.8"
        assert response.mapped_address == "192.168.1.1"
        assert response.changed_address is None


class TestSTUNClient:
    """Tests for STUNClient."""

    def test_client_creation(self):
        client = STUNClient(("stun.example.com", 3478))
        assert client.server == ("stun.example.com", 3478)

    def test_default_server(self):
        client = STUNClient()
        assert client.server[0] == "stun.l.google.com"


class TestHolePuncher:
    """Tests for HolePuncher."""

    def test_puncher_creation(self):
        puncher = HolePuncher()
        assert len(puncher._pending_sessions) == 0
        assert len(puncher._punch_attempts) == 0

    def test_record_punch_attempt(self):
        puncher = HolePuncher()
        puncher.record_punch_attempt("peer-1")
        assert puncher.get_punch_attempts("peer-1") == 1
        puncher.record_punch_attempt("peer-1")
        assert puncher.get_punch_attempts("peer-1") == 2

    @pytest.mark.asyncio
    async def test_initiate_hole_punch(self):
        puncher = HolePuncher()
        with patch.object(puncher, 'dht_callback', AsyncMock()):
            future = asyncio.get_event_loop().create_future()
            puncher._pending_sessions["peer-1"] = future
            future.set_result(NATEndpoint("192.168.1.1", 8080, NATType.OPEN))
            result = await puncher.initiate_hole_punch("peer-1", {})
            assert result is not None

    @pytest.mark.asyncio
    async def test_initiate_hole_punch_timeout(self):
        puncher = HolePuncher()
        with patch.object(puncher, 'dht_callback', None):
            result = await puncher.initiate_hole_punch("peer-1", {}, timeout=0.1)
            assert result is None


class TestPortPredictor:
    """Tests for PortPredictor."""

    def test_predictor_creation(self):
        predictor = PortPredictor()
        assert len(predictor._port_mappings) == 0

    def test_add_mapping(self):
        predictor = PortPredictor()
        predictor.add_mapping(5000, 6000)
        assert len(predictor._port_mappings) == 1

    def test_predict_next_port_insufficient_data(self):
        predictor = PortPredictor()
        result = predictor.predict_next_port(5000)
        assert result is None

    def test_predict_next_port_with_data(self):
        predictor = PortPredictor()
        predictor.add_mapping(5000, 6000)
        predictor.add_mapping(5001, 6001)
        predictor.add_mapping(5002, 6002)
        predictor.add_mapping(5003, 6003)
        predictor.add_mapping(5004, 6004)
        result = predictor.predict_next_port(5004)
        assert result == 6005


class TestUPNPManager:
    """Tests for UPNPManager."""

    def test_manager_creation(self):
        manager = UPNPManager()
        assert len(manager._mappings) == 0
        assert manager._enabled is False

    @pytest.mark.asyncio
    async def test_discover_fails_without_miniupnpc(self):
        manager = UPNPManager()
        with patch('meshbox.nat.traversal.miniupnpc', None):
            result = await manager.discover()
            assert result is False

    @pytest.mark.asyncio
    async def test_cleanup_all(self):
        manager = UPNPManager()
        manager._mappings[5000] = {"external_port": 6000, "protocol": "UDP"}
        with patch.object(manager, 'remove_port_mapping', AsyncMock(return_value=True)):
            await manager.cleanup_all()
            assert len(manager._mappings) == 0

    def test_get_mappings(self):
        manager = UPNPManager()
        manager._mappings[5000] = {"external_port": 6000, "protocol": "UDP"}
        mappings = manager.get_mappings()
        assert 5000 in mappings


class TestNATTraversalEngine:
    """Tests for NATTraversalEngine."""

    @pytest.fixture
    def engine(self):
        return NATTraversalEngine(local_peer_id="test-peer", internal_port=7777)

    def test_engine_creation(self, engine):
        assert engine.local_peer_id == "test-peer"
        assert engine.internal_port == 7777
        assert engine.nat_type == NATType.UNKNOWN
        assert engine.external_endpoint is None

    def test_get_recommended_strategy(self, engine):
        engine.nat_type = NATType.OPEN
        strategy = engine.get_recommended_strategy()
        assert strategy["method"] == "direct"

        engine.nat_type = NATType.SYMMETRIC
        strategy = engine.get_recommended_strategy()
        assert strategy["method"] == "hole_punch"

        engine.nat_type = NATType.UNKNOWN
        strategy = engine.get_recommended_strategy()
        assert strategy["method"] == "turn"


import asyncio
