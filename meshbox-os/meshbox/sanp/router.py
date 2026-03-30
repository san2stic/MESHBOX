"""
SANP Router — Distance-vector mesh routing table.

Implements a simplified Bellman-Ford routing algorithm.  Each entry maps a
``node_id`` to the best known next-hop .onion address, hop count, and
freshness information.

Routes are exchanged via ``ROUTE`` frames and periodically broadcast to
direct peers.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("meshbox.sanp.router")

# Route expires if not refreshed within this window
ROUTE_EXPIRY_SECONDS = 600  # 10 minutes
MAX_HOPS = 20


@dataclass
class RouteEntry:
    """A single routing-table entry."""

    node_id: str
    onion_address: str
    next_hop: str  # node_id of the direct peer forwarding to destination
    hops: int
    latency_ms: float = 0.0
    last_seen: float = field(default_factory=time.time)

    @property
    def is_expired(self) -> bool:
        return (time.time() - self.last_seen) > ROUTE_EXPIRY_SECONDS


class SANPRouter:
    """Mesh routing table with Bellman-Ford distance-vector updates.

    The router maintains a dict ``node_id → RouteEntry`` and provides
    methods to add / remove / query routes and to serialise the table
    for ROUTE frame broadcasts.
    """

    def __init__(self, local_node_id: str) -> None:
        self.local_node_id = local_node_id
        self.routing_table: dict[str, RouteEntry] = {}

    # ------------------------------------------------------------------
    # Table manipulation
    # ------------------------------------------------------------------

    def add_route(
        self,
        node_id: str,
        onion_address: str,
        next_hop: str,
        hops: int,
        latency_ms: float = 0.0,
    ) -> bool:
        """Add or update a route.  Returns True if the table changed."""
        if node_id == self.local_node_id:
            return False
        if hops > MAX_HOPS:
            return False

        existing = self.routing_table.get(node_id)
        if existing is None or hops < existing.hops or (
            hops == existing.hops and latency_ms < existing.latency_ms
        ):
            self.routing_table[node_id] = RouteEntry(
                node_id=node_id,
                onion_address=onion_address,
                next_hop=next_hop,
                hops=hops,
                latency_ms=latency_ms,
                last_seen=time.time(),
            )
            logger.debug(
                "Route updated: %s via %s (%d hops, %.1fms)",
                node_id[:12],
                next_hop[:12],
                hops,
                latency_ms,
            )
            return True

        # Refresh last_seen even if route is not better
        if existing.next_hop == next_hop:
            existing.last_seen = time.time()
        return False

    def remove_route(self, node_id: str) -> None:
        """Remove a route from the table."""
        self.routing_table.pop(node_id, None)

    def get_best_route(self, node_id: str) -> Optional[str]:
        """Return the .onion address of the best route to *node_id*, or None."""
        entry = self.routing_table.get(node_id)
        if entry and not entry.is_expired:
            return entry.onion_address
        return None

    def get_next_hop(self, node_id: str) -> Optional[str]:
        """Return the next-hop node_id for reaching *node_id*."""
        entry = self.routing_table.get(node_id)
        if entry and not entry.is_expired:
            return entry.next_hop
        return None

    def get_route_entry(self, node_id: str) -> Optional[RouteEntry]:
        entry = self.routing_table.get(node_id)
        if entry and not entry.is_expired:
            return entry
        return None

    # ------------------------------------------------------------------
    # Bellman-Ford update
    # ------------------------------------------------------------------

    def apply_route_update(
        self,
        sender_node_id: str,
        sender_onion: str,
        routes: list[dict],
    ) -> int:
        """Apply a batch of route announcements from a peer.

        Each entry in *routes* is a dict with keys:
        ``node_id``, ``onion_address``, ``hops``, ``latency_ms``.

        Returns the number of routes that changed.
        """
        changes = 0
        for r in routes:
            nid = r["node_id"] if isinstance(r["node_id"], str) else r["node_id"].decode()
            onion = r["onion_address"] if isinstance(r["onion_address"], str) else r["onion_address"].decode()
            hops = r["hops"] + 1  # one additional hop through sender
            latency = r.get("latency_ms", 0.0)
            if self.add_route(
                node_id=nid,
                onion_address=onion,
                next_hop=sender_node_id,
                hops=hops,
                latency_ms=latency,
            ):
                changes += 1
        return changes

    # ------------------------------------------------------------------
    # Broadcast / serialisation
    # ------------------------------------------------------------------

    def export_routes(self) -> list[dict]:
        """Export the routing table for inclusion in a ROUTE frame payload."""
        self.cleanup_expired()
        return [
            {
                "node_id": e.node_id,
                "onion_address": e.onion_address,
                "hops": e.hops,
                "latency_ms": e.latency_ms,
            }
            for e in self.routing_table.values()
        ]

    def get_topology(self) -> dict:
        """Return a JSON-friendly topology snapshot for the API/dashboard."""
        self.cleanup_expired()
        nodes = [
            {
                "node_id": e.node_id,
                "onion_address": e.onion_address,
                "hops": e.hops,
                "latency_ms": e.latency_ms,
                "next_hop": e.next_hop,
                "last_seen": e.last_seen,
            }
            for e in self.routing_table.values()
        ]
        return {
            "local_node_id": self.local_node_id,
            "routes": nodes,
            "total": len(nodes),
        }

    # ------------------------------------------------------------------
    # Maintenance
    # ------------------------------------------------------------------

    def cleanup_expired(self) -> int:
        """Remove expired routes.  Returns the number removed."""
        expired = [
            nid for nid, e in self.routing_table.items() if e.is_expired
        ]
        for nid in expired:
            del self.routing_table[nid]
        if expired:
            logger.debug("Cleaned %d expired routes", len(expired))
        return len(expired)

    def invalidate_via(self, failed_node_id: str) -> int:
        """Remove all routes whose next_hop is *failed_node_id*."""
        to_remove = [
            nid
            for nid, e in self.routing_table.items()
            if e.next_hop == failed_node_id
        ]
        for nid in to_remove:
            del self.routing_table[nid]
        return len(to_remove)

    def __len__(self) -> int:
        return len(self.routing_table)

    def __contains__(self, node_id: str) -> bool:
        entry = self.routing_table.get(node_id)
        return entry is not None and not entry.is_expired
