"""
SANP Gossip Engine — Epidemic information dissemination.

Implements a probabilistic gossip protocol where each published message is
forwarded to a random subset of peers (fan-out).  Messages are deduplicated
via a TTL-based msg_id cache to prevent infinite loops.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine, Optional

logger = logging.getLogger("meshbox.sanp.gossip")

# Dedup cache TTL
MSG_CACHE_TTL = 300  # 5 minutes
MSG_CACHE_MAX = 50_000
DEFAULT_FANOUT = 3


@dataclass
class GossipMessage:
    """An individual gossip message."""

    msg_id: bytes
    topic: str
    data: Any
    origin_node_id: str
    timestamp: float = field(default_factory=time.time)
    ttl: int = 10  # max number of hops


class GossipEngine:
    """Epidemic gossip engine for broadcasting information across the mesh.

    Usage::

        engine = GossipEngine(identity, peer_manager, fanout=3)
        engine.subscribe("peer_announce", my_handler)
        await engine.publish("peer_announce", {"onion": "abc.onion"})
    """

    def __init__(
        self,
        local_node_id: str,
        fanout: int = DEFAULT_FANOUT,
    ) -> None:
        self.local_node_id = local_node_id
        self.fanout = fanout

        # topic → list of async callbacks
        self._subscribers: dict[str, list[Callable[..., Coroutine]]] = {}

        # msg_id (hex) → timestamp for deduplication
        self._seen: OrderedDict[str, float] = OrderedDict()

        # Callback to actually send a GOSSIP frame to a peer.
        # Set by the daemon after initialisation.
        self._send_to_peer: Optional[
            Callable[[str, Any], Coroutine]
        ] = None

        # Active peers callback — returns list of (node_id, onion_address)
        self._get_peers: Optional[Callable[[], list[tuple[str, str]]]] = None

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def set_send_callback(
        self, cb: Callable[[str, Any], Coroutine]
    ) -> None:
        """Register the function that sends a gossip frame to a peer node_id."""
        self._send_to_peer = cb

    def set_peers_callback(
        self, cb: Callable[[], list[tuple[str, str]]]
    ) -> None:
        """Register a function returning currently connected peers."""
        self._get_peers = cb

    # ------------------------------------------------------------------
    # Pub / Sub
    # ------------------------------------------------------------------

    def subscribe(
        self,
        topic: str,
        callback: Callable[[GossipMessage], Coroutine],
    ) -> None:
        """Subscribe to a gossip *topic*."""
        self._subscribers.setdefault(topic, []).append(callback)

    def unsubscribe(self, topic: str, callback: Callable) -> None:
        subs = self._subscribers.get(topic, [])
        if callback in subs:
            subs.remove(callback)

    async def publish(self, topic: str, data: Any) -> bytes:
        """Publish a message to the network.  Returns the msg_id."""
        msg_id = os.urandom(8)
        msg = GossipMessage(
            msg_id=msg_id,
            topic=topic,
            data=data,
            origin_node_id=self.local_node_id,
        )
        self._mark_seen(msg_id)
        await self._propagate(msg)
        return msg_id

    async def handle_incoming(self, raw_payload: dict) -> None:
        """Handle a received GOSSIP frame payload from a peer."""
        msg_id = raw_payload[b"msg_id"] if b"msg_id" in raw_payload else raw_payload.get("msg_id", b"")
        topic = raw_payload[b"topic"] if b"topic" in raw_payload else raw_payload.get("topic", "")
        if isinstance(topic, bytes):
            topic = topic.decode()
        data = raw_payload[b"data"] if b"data" in raw_payload else raw_payload.get("data")
        origin = raw_payload[b"origin"] if b"origin" in raw_payload else raw_payload.get("origin", "")
        if isinstance(origin, bytes):
            origin = origin.decode()
        ttl = raw_payload.get(b"ttl", raw_payload.get("ttl", 10))

        # Dedup check
        if self._is_seen(msg_id):
            return

        self._mark_seen(msg_id)

        msg = GossipMessage(
            msg_id=msg_id,
            topic=topic,
            data=data,
            origin_node_id=origin,
            ttl=ttl - 1,
        )

        # Notify local subscribers
        for cb in self._subscribers.get(topic, []):
            try:
                await cb(msg)
            except Exception as exc:
                logger.warning("Gossip subscriber error: %s", exc)

        # Re-propagate if TTL allows
        if msg.ttl > 0:
            await self._propagate(msg)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _propagate(self, msg: GossipMessage) -> None:
        """Forward the message to a random subset of peers (fan-out)."""
        if self._get_peers is None or self._send_to_peer is None:
            return

        peers = self._get_peers()
        # Exclude origin node from forwarding targets
        candidates = [
            (nid, onion)
            for nid, onion in peers
            if nid != msg.origin_node_id
        ]

        if not candidates:
            return

        import random

        targets = random.sample(candidates, min(self.fanout, len(candidates)))

        payload = {
            b"msg_id": msg.msg_id,
            b"topic": msg.topic.encode() if isinstance(msg.topic, str) else msg.topic,
            b"data": msg.data,
            b"origin": msg.origin_node_id.encode() if isinstance(msg.origin_node_id, str) else msg.origin_node_id,
            b"ttl": msg.ttl,
        }

        for nid, _onion in targets:
            try:
                await self._send_to_peer(nid, payload)
            except Exception as exc:
                logger.debug("Gossip send to %s failed: %s", nid[:12], exc)

    def _is_seen(self, msg_id: bytes) -> bool:
        key = msg_id.hex()
        entry = self._seen.get(key)
        if entry is None:
            return False
        if time.time() - entry > MSG_CACHE_TTL:
            del self._seen[key]
            return False
        return True

    def _mark_seen(self, msg_id: bytes) -> None:
        key = msg_id.hex()
        self._seen[key] = time.time()
        # Evict oldest entries if cache is full
        while len(self._seen) > MSG_CACHE_MAX:
            self._seen.popitem(last=False)

    def cleanup(self) -> int:
        """Remove expired entries from the dedup cache.  Returns count removed."""
        now = time.time()
        expired = [k for k, ts in self._seen.items() if now - ts > MSG_CACHE_TTL]
        for k in expired:
            del self._seen[k]
        return len(expired)
