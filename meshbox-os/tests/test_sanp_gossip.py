"""Tests for meshbox.sanp.gossip."""

import asyncio

import pytest

from meshbox.sanp.gossip import GossipEngine, GossipMessage


class TestGossipEngine:
    def test_dedup(self):
        engine = GossipEngine("local-node")
        msg_id = b"\x01" * 8
        engine._mark_seen(msg_id)
        assert engine._is_seen(msg_id) is True
        assert engine._is_seen(b"\x02" * 8) is False

    @pytest.mark.asyncio
    async def test_publish_calls_send(self):
        sent_messages = []

        async def mock_send(node_id, payload):
            sent_messages.append((node_id, payload))

        def mock_peers():
            return [("peer-1", "a.onion"), ("peer-2", "b.onion")]

        engine = GossipEngine("local-node", fanout=2)
        engine.set_send_callback(mock_send)
        engine.set_peers_callback(mock_peers)

        msg_id = await engine.publish("test_topic", {"key": "value"})
        assert len(msg_id) == 8
        assert len(sent_messages) == 2

    @pytest.mark.asyncio
    async def test_subscribe_receives_messages(self):
        received = []

        async def handler(msg: GossipMessage):
            received.append(msg)

        engine = GossipEngine("local-node")
        engine.subscribe("my_topic", handler)

        await engine.handle_incoming({
            b"msg_id": b"\x99" * 8,
            b"topic": b"my_topic",
            b"data": {b"info": b"test"},
            b"origin": b"other-node",
            b"ttl": 5,
        })

        assert len(received) == 1
        assert received[0].topic == "my_topic"

    @pytest.mark.asyncio
    async def test_duplicate_messages_ignored(self):
        received = []

        async def handler(msg):
            received.append(msg)

        engine = GossipEngine("local-node")
        engine.subscribe("topic", handler)

        msg = {
            b"msg_id": b"\xAA" * 8,
            b"topic": b"topic",
            b"data": b"test",
            b"origin": b"other",
            b"ttl": 5,
        }

        await engine.handle_incoming(msg)
        await engine.handle_incoming(msg)  # duplicate

        assert len(received) == 1

    def test_cleanup(self):
        engine = GossipEngine("local")
        import time
        # Add some entries and manually expire them
        for i in range(10):
            engine._seen[f"key{i}"] = time.time() - 600
        removed = engine.cleanup()
        assert removed == 10
