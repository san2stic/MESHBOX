"""Tests for meshbox.sanp.peer_manager."""

import time

import pytest

from meshbox.sanp.peer_manager import PeerManager, PeerInfo, PEER_TIMEOUT


class TestPeerManager:
    def test_add_peer(self):
        pm = PeerManager("local-node")
        added = pm.add_peer("peer-1", "abc.onion")
        assert added is True
        assert pm.get_peer("peer-1") is not None

    def test_add_self_ignored(self):
        pm = PeerManager("local-node")
        assert pm.add_peer("local-node", "x.onion") is False

    def test_add_duplicate_updates(self):
        pm = PeerManager("local")
        pm.add_peer("peer-1", "old.onion")
        added = pm.add_peer("peer-1", "new.onion")
        assert added is False  # not newly added
        assert pm.get_peer("peer-1").onion_address == "new.onion"

    def test_remove_peer(self):
        pm = PeerManager("local")
        pm.add_peer("peer-1", "a.onion")
        pm.remove_peer("peer-1")
        assert pm.get_peer("peer-1") is None

    def test_connected_count(self):
        pm = PeerManager("local")
        pm.add_peer("p1", "a.onion")
        pm.add_peer("p2", "b.onion")
        pm.mark_connected("p1")
        assert pm.connected_count == 1

    def test_needs_more_peers(self):
        pm = PeerManager("local", min_peers=3)
        assert pm.needs_more_peers is True
        for i in range(3):
            pm.add_peer(f"p{i}", f"{i}.onion")
            pm.mark_connected(f"p{i}")
        assert pm.needs_more_peers is False

    def test_can_accept_peer(self):
        pm = PeerManager("local", max_peers=2)
        pm.add_peer("p1", "a.onion")
        pm.mark_connected("p1")
        pm.add_peer("p2", "b.onion")
        pm.mark_connected("p2")
        assert pm.can_accept_peer is False

    def test_blacklist(self):
        pm = PeerManager("local")
        pm.blacklist("bad-peer", duration=100)
        assert pm.is_blacklisted("bad-peer") is True
        assert pm.add_peer("bad-peer", "x.onion") is False

    def test_blacklist_expires(self):
        pm = PeerManager("local")
        pm.blacklist("bad-peer", duration=0)
        # Should immediately expire
        time.sleep(0.01)
        assert pm.is_blacklisted("bad-peer") is False

    def test_record_failure_blacklists_after_5(self):
        pm = PeerManager("local")
        pm.add_peer("flaky", "f.onion")
        for _ in range(5):
            pm.record_failure("flaky")
        assert pm.is_blacklisted("flaky") is True
        assert pm.get_peer("flaky") is None  # removed

    def test_export_import_peer_list(self):
        pm1 = PeerManager("node-1")
        pm1.add_peer("p1", "a.onion", pubkey_ed25519=b"\x01" * 32)
        pm1.add_peer("p2", "b.onion", pubkey_ed25519=b"\x02" * 32)

        exported = pm1.export_peer_list()
        assert len(exported) == 2

        pm2 = PeerManager("node-2")
        added = pm2.import_peer_list(exported)
        assert added == 2

    def test_cleanup_stale(self):
        pm = PeerManager("local")
        pm.add_peer("stale", "s.onion")
        pm.peers["stale"].last_seen = time.time() - PEER_TIMEOUT - 10
        removed = pm.cleanup_stale()
        assert removed == 1
        assert pm.get_peer("stale") is None

    def test_get_stats(self):
        pm = PeerManager("local")
        pm.add_peer("p1", "a.onion")
        pm.mark_connected("p1")
        stats = pm.get_stats()
        assert stats["total_peers"] == 1
        assert stats["connected"] == 1
