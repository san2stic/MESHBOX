"""Tests for meshbox.sanp.router — Distance-vector mesh routing."""

import time

import pytest

from meshbox.sanp.router import SANPRouter, RouteEntry, ROUTE_EXPIRY_SECONDS


class TestSANPRouter:
    def test_add_route(self):
        router = SANPRouter("local-node-id")
        changed = router.add_route("peer-1", "abc.onion", "peer-1", hops=1)
        assert changed is True
        assert "peer-1" in router
        assert len(router) == 1

    def test_ignores_self_route(self):
        router = SANPRouter("local-node-id")
        changed = router.add_route("local-node-id", "abc.onion", "x", hops=1)
        assert changed is False

    def test_shorter_route_wins(self):
        router = SANPRouter("local")
        router.add_route("peer-1", "a.onion", "via-a", hops=3)
        router.add_route("peer-1", "a.onion", "via-b", hops=1)

        entry = router.get_route_entry("peer-1")
        assert entry.hops == 1
        assert entry.next_hop == "via-b"

    def test_longer_route_ignored(self):
        router = SANPRouter("local")
        router.add_route("peer-1", "a.onion", "via-a", hops=1)
        changed = router.add_route("peer-1", "a.onion", "via-b", hops=5)
        assert changed is False

    def test_get_best_route(self):
        router = SANPRouter("local")
        router.add_route("peer-1", "abc.onion", "peer-1", hops=1)
        assert router.get_best_route("peer-1") == "abc.onion"
        assert router.get_best_route("unknown") is None

    def test_remove_route(self):
        router = SANPRouter("local")
        router.add_route("peer-1", "a.onion", "peer-1", hops=1)
        router.remove_route("peer-1")
        assert "peer-1" not in router

    def test_expired_routes_not_returned(self):
        router = SANPRouter("local")
        router.add_route("peer-1", "a.onion", "peer-1", hops=1)
        # Manually expire
        router.routing_table["peer-1"].last_seen = time.time() - ROUTE_EXPIRY_SECONDS - 10
        assert router.get_best_route("peer-1") is None

    def test_cleanup_expired(self):
        router = SANPRouter("local")
        router.add_route("peer-1", "a.onion", "peer-1", hops=1)
        router.add_route("peer-2", "b.onion", "peer-2", hops=1)
        router.routing_table["peer-1"].last_seen = time.time() - ROUTE_EXPIRY_SECONDS - 10
        removed = router.cleanup_expired()
        assert removed == 1
        assert len(router) == 1

    def test_invalidate_via(self):
        router = SANPRouter("local")
        router.add_route("peer-A", "a.onion", "relay-1", hops=2)
        router.add_route("peer-B", "b.onion", "relay-1", hops=3)
        router.add_route("peer-C", "c.onion", "relay-2", hops=1)
        removed = router.invalidate_via("relay-1")
        assert removed == 2
        assert len(router) == 1

    def test_export_routes(self):
        router = SANPRouter("local")
        router.add_route("peer-1", "a.onion", "peer-1", hops=1, latency_ms=50.0)
        routes = router.export_routes()
        assert len(routes) == 1
        assert routes[0]["node_id"] == "peer-1"
        assert routes[0]["hops"] == 1

    def test_apply_route_update(self):
        router = SANPRouter("local")
        updates = [
            {"node_id": "peer-A", "onion_address": "a.onion", "hops": 1, "latency_ms": 10},
            {"node_id": "peer-B", "onion_address": "b.onion", "hops": 2, "latency_ms": 20},
        ]
        changes = router.apply_route_update("sender-1", "sender.onion", updates)
        assert changes == 2
        # Hops should be +1 (via sender)
        assert router.routing_table["peer-A"].hops == 2
        assert router.routing_table["peer-B"].hops == 3

    def test_get_topology(self):
        router = SANPRouter("local-id")
        router.add_route("peer-1", "a.onion", "peer-1", hops=1)
        topo = router.get_topology()
        assert topo["local_node_id"] == "local-id"
        assert topo["total"] == 1

    def test_max_hops_rejected(self):
        router = SANPRouter("local")
        changed = router.add_route("far-node", "far.onion", "via", hops=25)
        assert changed is False
