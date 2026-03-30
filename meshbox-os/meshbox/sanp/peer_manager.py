"""
SANP Peer Manager — Tracks connected peers, keepalive, and blacklisting.

Maintains a registry of all known peers with their identity information,
connection state, and health metrics.  Handles PING/PONG keepalive and
temporary blacklisting of misbehaving peers.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("meshbox.sanp.peer_manager")

# Defaults
KEEPALIVE_INTERVAL = 60  # seconds
PEER_TIMEOUT = 180  # seconds — peer is stale after this
BLACKLIST_DURATION = 3600  # seconds (1 hour)
MAX_PEERS = 8
MIN_PEERS = 3


@dataclass
class PeerInfo:
    """Metadata about a known peer."""

    node_id: str
    onion_address: str
    pubkey_ed25519: bytes = b""
    pubkey_x25519: bytes = b""
    connected_since: float = 0.0
    last_seen: float = field(default_factory=time.time)
    latency_ms: float = 0.0
    hops: int = 1  # direct peer = 1
    is_connected: bool = False
    failed_attempts: int = 0

    def is_stale(self, timeout: float = PEER_TIMEOUT) -> bool:
        return (time.time() - self.last_seen) > timeout

    def touch(self) -> None:
        self.last_seen = time.time()


class PeerManager:
    """Manages the set of connected peers and their health.

    Provides methods to add/remove peers, request more peers from
    existing connections, and maintains keepalive via PING/PONG.
    """

    def __init__(
        self,
        local_node_id: str,
        max_peers: int = MAX_PEERS,
        min_peers: int = MIN_PEERS,
    ) -> None:
        self.local_node_id = local_node_id
        self.max_peers = max_peers
        self.min_peers = min_peers

        self.peers: dict[str, PeerInfo] = {}
        self._blacklist: dict[str, float] = {}  # node_id → expiry timestamp

    # ------------------------------------------------------------------
    # Peer lifecycle
    # ------------------------------------------------------------------

    def add_peer(
        self,
        node_id: str,
        onion_address: str,
        pubkey_ed25519: bytes = b"",
        pubkey_x25519: bytes = b"",
        hops: int = 1,
    ) -> bool:
        """Add or update a peer.  Returns True if newly added."""
        if node_id == self.local_node_id:
            return False
        if self.is_blacklisted(node_id):
            return False

        existing = self.peers.get(node_id)
        if existing:
            existing.onion_address = onion_address
            if pubkey_ed25519:
                existing.pubkey_ed25519 = pubkey_ed25519
            if pubkey_x25519:
                existing.pubkey_x25519 = pubkey_x25519
            existing.touch()
            return False

        peer = PeerInfo(
            node_id=node_id,
            onion_address=onion_address,
            pubkey_ed25519=pubkey_ed25519,
            pubkey_x25519=pubkey_x25519,
            connected_since=time.time(),
            hops=hops,
        )
        self.peers[node_id] = peer
        logger.info("Peer added: %s (%s)", node_id[:12], onion_address[:20])
        return True

    def remove_peer(self, node_id: str) -> None:
        """Remove a peer from the active set."""
        if node_id in self.peers:
            del self.peers[node_id]
            logger.info("Peer removed: %s", node_id[:12])

    def mark_connected(self, node_id: str) -> None:
        peer = self.peers.get(node_id)
        if peer:
            peer.is_connected = True
            peer.connected_since = time.time()
            peer.touch()

    def mark_disconnected(self, node_id: str) -> None:
        peer = self.peers.get(node_id)
        if peer:
            peer.is_connected = False

    def record_failure(self, node_id: str) -> None:
        """Record a connection failure.  Blacklist after 5 consecutive failures."""
        peer = self.peers.get(node_id)
        if peer:
            peer.failed_attempts += 1
            if peer.failed_attempts >= 5:
                self.blacklist(node_id)
                self.remove_peer(node_id)

    def record_pong(self, node_id: str, latency_ms: float) -> None:
        """Update peer latency from a PONG response."""
        peer = self.peers.get(node_id)
        if peer:
            peer.latency_ms = latency_ms
            peer.failed_attempts = 0
            peer.touch()

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_peer(self, node_id: str) -> Optional[PeerInfo]:
        return self.peers.get(node_id)

    def get_active_peers(self) -> list[PeerInfo]:
        """Return connected, non-stale peers."""
        return [
            p
            for p in self.peers.values()
            if p.is_connected and not p.is_stale()
        ]

    def get_all_peers(self) -> list[PeerInfo]:
        return list(self.peers.values())

    def get_connected_node_ids(self) -> list[tuple[str, str]]:
        """Return list of (node_id, onion_address) for active peers."""
        return [
            (p.node_id, p.onion_address) for p in self.get_active_peers()
        ]

    @property
    def connected_count(self) -> int:
        return len(self.get_active_peers())

    @property
    def needs_more_peers(self) -> bool:
        return self.connected_count < self.min_peers

    @property
    def can_accept_peer(self) -> bool:
        return self.connected_count < self.max_peers

    # ------------------------------------------------------------------
    # Blacklist
    # ------------------------------------------------------------------

    def blacklist(
        self, node_id: str, duration: float = BLACKLIST_DURATION
    ) -> None:
        self._blacklist[node_id] = time.time() + duration
        logger.warning("Peer blacklisted: %s for %ds", node_id[:12], duration)

    def is_blacklisted(self, node_id: str) -> bool:
        expiry = self._blacklist.get(node_id)
        if expiry is None:
            return False
        if time.time() > expiry:
            del self._blacklist[node_id]
            return False
        return True

    def clear_blacklist(self) -> None:
        self._blacklist.clear()

    # ------------------------------------------------------------------
    # Peer exchange helpers
    # ------------------------------------------------------------------

    def export_peer_list(self, max_entries: int = 20) -> list[dict]:
        """Export a list of known peers for PEER_LIST frames.

        Only exports peers we have full identity info for.
        """
        entries = []
        for p in self.peers.values():
            if p.pubkey_ed25519 and p.onion_address:
                entries.append(
                    {
                        b"node_id": p.node_id.encode(),
                        b"onion_address": p.onion_address.encode(),
                        b"pubkey_ed25519": p.pubkey_ed25519,
                        b"pubkey_x25519": p.pubkey_x25519,
                    }
                )
            if len(entries) >= max_entries:
                break
        return entries

    def import_peer_list(self, entries: list[dict]) -> int:
        """Import peers from a received PEER_LIST.  Returns count of new peers."""
        added = 0
        for entry in entries:
            nid = entry[b"node_id"]
            if isinstance(nid, bytes):
                nid = nid.decode()
            onion = entry[b"onion_address"]
            if isinstance(onion, bytes):
                onion = onion.decode()
            pk_ed = entry.get(b"pubkey_ed25519", b"")
            pk_x = entry.get(b"pubkey_x25519", b"")
            if self.add_peer(nid, onion, pk_ed, pk_x):
                added += 1
        return added

    # ------------------------------------------------------------------
    # Maintenance
    # ------------------------------------------------------------------

    def cleanup_stale(self) -> int:
        """Remove stale peers.  Returns count removed."""
        stale = [
            nid
            for nid, p in self.peers.items()
            if p.is_stale() and not p.is_connected
        ]
        for nid in stale:
            del self.peers[nid]
        if stale:
            logger.debug("Cleaned %d stale peers", len(stale))

        # Also clean expired blacklist entries
        now = time.time()
        expired_bl = [
            nid for nid, exp in self._blacklist.items() if now > exp
        ]
        for nid in expired_bl:
            del self._blacklist[nid]

        return len(stale)

    def get_stats(self) -> dict:
        """Return summary statistics."""
        return {
            "total_peers": len(self.peers),
            "connected": self.connected_count,
            "blacklisted": len(self._blacklist),
            "needs_more": self.needs_more_peers,
        }
