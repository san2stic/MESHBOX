"""Tests for meshbox.node.dht — Kademlia DHT."""

import pytest

from meshbox.node.dht import KademliaNode, _xor_distance, _bucket_index


class TestKademliaHelpers:
    def test_xor_distance_same(self):
        a = b"\x00" * 32
        assert _xor_distance(a, a) == 0

    def test_xor_distance_different(self):
        a = b"\x00" * 32
        b = b"\x00" * 31 + b"\x01"
        assert _xor_distance(a, b) == 1

    def test_bucket_index_zero(self):
        assert _bucket_index(0) == 0

    def test_bucket_index_one(self):
        assert _bucket_index(1) == 0

    def test_bucket_index_large(self):
        assert _bucket_index(2**255) == 255


class TestKademliaNode:
    def _make_node(self, hex_suffix="00"):
        nid = hex_suffix.rjust(64, "0")
        return KademliaNode(nid, "test.onion")

    def test_add_contact(self):
        node = self._make_node("01")
        node.add_contact("0" * 63 + "2", "peer.onion")
        assert node.total_contacts == 1

    def test_add_self_ignored(self):
        nid = "0" * 64
        node = KademliaNode(nid, "test.onion")
        node.add_contact(nid, "self.onion")
        assert node.total_contacts == 0

    def test_find_closest(self):
        node = self._make_node("00")
        for i in range(1, 10):
            nid = hex(i)[2:].rjust(64, "0")
            node.add_contact(nid, f"peer{i}.onion")

        target = "0" * 63 + "5"
        closest = node.find_closest(target, count=3)
        assert len(closest) == 3
        # The closest should include node_id "...5"
        ids = [c.node_id for c in closest]
        assert target in ids

    def test_store_and_find_local(self):
        node = self._make_node("00")
        import asyncio
        asyncio.run(node.store("test_key", {"data": 42}))
        value = asyncio.run(node.find_value("test_key"))
        assert value == {"data": 42}

    def test_handle_store(self):
        import hashlib
        node = self._make_node("00")
        key = "my_key"
        key_hash = hashlib.sha3_256(key.encode()).hexdigest()
        ok = node.handle_store(key, key_hash, "my_value")
        assert ok is True
        assert node.handle_find_value(key_hash) == "my_value"

    def test_handle_store_rejects_bad_hash(self):
        node = self._make_node("00")
        ok = node.handle_store("key", "wrong_hash", "value")
        assert ok is False

    def test_cleanup_expired(self):
        import time
        node = self._make_node("00")
        import hashlib
        key_hash = hashlib.sha3_256(b"old").hexdigest()
        from meshbox.node.dht import StoredValue
        node._store[key_hash] = StoredValue(key="old", value="data", stored_at=time.time() - 7200, ttl=3600)
        removed = node.cleanup_expired()
        assert removed == 1

    def test_handle_find_node(self):
        node = self._make_node("00")
        for i in range(5):
            nid = hex(i + 1)[2:].rjust(64, "0")
            node.add_contact(nid, f"p{i}.onion")

        result = node.handle_find_node("0" * 63 + "3")
        assert len(result) == 5
        assert all("node_id" in r for r in result)
