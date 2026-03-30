"""
Rendezvous — Tor-based rendezvous for initial network discovery.

Allows new nodes to join the mesh without hardcoded seed addresses by
publishing their identity to a well-known DHT topic that all nodes monitor.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Optional

logger = logging.getLogger("meshbox.node.rendezvous")

# Well-known DHT key for the rendezvous directory
RENDEZVOUS_TOPIC = "meshbox_rendezvous_v1"
ANNOUNCE_INTERVAL = 300  # 5 minutes


class RendezvousService:
    """Publishes and discovers peers via DHT rendezvous.

    Periodically announces our own address and fetches the list of other
    nodes from the well-known rendezvous key in the DHT.
    """

    def __init__(
        self,
        node_id: str,
        onion_address: str,
        dht: "KademliaNode",
        peer_manager: "PeerManager",
    ) -> None:
        self.node_id = node_id
        self.onion_address = onion_address
        self.dht = dht
        self.peer_manager = peer_manager
        self._running = False

    async def start(self) -> None:
        self._running = True
        logger.info("Rendezvous service started")
        asyncio.create_task(self._announce_loop())
        asyncio.create_task(self._discover_loop())

    async def stop(self) -> None:
        self._running = False

    # ------------------------------------------------------------------
    # Announce
    # ------------------------------------------------------------------

    async def _announce_loop(self) -> None:
        while self._running:
            try:
                await self.announce()
            except Exception as exc:
                logger.warning("Rendezvous announce failed: %s", exc)
            await asyncio.sleep(ANNOUNCE_INTERVAL)

    async def announce(self) -> None:
        """Publish our identity to the rendezvous DHT key."""
        entry = {
            "node_id": self.node_id,
            "onion_address": self.onion_address,
            "timestamp": time.time(),
        }
        # We store under a composite key so multiple nodes can coexist
        key = f"{RENDEZVOUS_TOPIC}:{self.node_id}"
        await self.dht.store(key, entry, ttl=600)
        logger.debug("Rendezvous: announced as %s", self.onion_address[:20])

    # ------------------------------------------------------------------
    # Discover
    # ------------------------------------------------------------------

    async def _discover_loop(self) -> None:
        while self._running:
            try:
                await self.discover()
            except Exception as exc:
                logger.debug("Rendezvous discover failed: %s", exc)
            await asyncio.sleep(ANNOUNCE_INTERVAL)

    async def discover(self) -> int:
        """Look up the rendezvous key and add discovered peers.

        Returns the number of new peers found.
        """
        # Find nodes close to the rendezvous key hash
        import hashlib

        target = hashlib.sha3_256(RENDEZVOUS_TOPIC.encode()).hexdigest()
        nodes = await self.dht.find_node(target)

        added = 0
        for node_info in nodes:
            nid = node_info["node_id"]
            onion = node_info["onion_address"]
            if nid != self.node_id and self.peer_manager.can_accept_peer:
                if self.peer_manager.add_peer(nid, onion):
                    added += 1

        if added:
            logger.info("Rendezvous: discovered %d new peers", added)
        return added
