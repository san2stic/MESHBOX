"""
MeshBox - Directory service v4.
Decentralized peer directory for the MeshBox Tor network.
- Announces local node to directory nodes
- Discovers peers via directory queries
- Gossip protocol for peer sharing between nodes
- Bootstrap from hardcoded or configured directory nodes
"""

import asyncio
import json
import logging
import time
from typing import Optional

from meshbox.config import (
    DIRECTORY_BOOTSTRAP_NODES, DIRECTORY_ANNOUNCE_INTERVAL,
)
from meshbox.storage import StorageEngine

logger = logging.getLogger("meshbox.directory")


class DirectoryClient:
    """Client for the MeshBox decentralized directory service."""

    def __init__(self, storage: StorageEngine, tor_manager, profile: dict):
        self.storage = storage
        self.tor = tor_manager
        self.profile = profile
        self._running = False
        self._is_directory_node = False

    @property
    def is_directory_node(self) -> bool:
        return self._is_directory_node

    def set_directory_mode(self, enabled: bool):
        """Enable or disable directory node mode."""
        self._is_directory_node = enabled
        if enabled:
            logger.info("Directory node mode ENABLED - this node will serve as a directory")
        else:
            logger.info("Directory node mode DISABLED")

    async def start(self):
        """Start the directory client: announce and discover peers."""
        self._running = True

        tasks = [
            asyncio.create_task(self._announce_loop()),
            asyncio.create_task(self._discover_loop()),
        ]

        logger.info("Directory client started")

        try:
            await asyncio.gather(*tasks, return_exceptions=True)
        except asyncio.CancelledError:
            pass

    def stop(self):
        self._running = False

    async def _announce_loop(self):
        """Periodically announce our presence to directory nodes."""
        # Initial delay to let Tor stabilize
        await asyncio.sleep(10)

        while self._running:
            try:
                await self._announce()
            except Exception as e:
                logger.debug("Announce error: %s", e)
            await asyncio.sleep(DIRECTORY_ANNOUNCE_INTERVAL)

    async def _discover_loop(self):
        """Periodically query directory nodes for new peers."""
        await asyncio.sleep(15)

        while self._running:
            try:
                await self._discover_peers()
            except Exception as e:
                logger.debug("Discover error: %s", e)
            await asyncio.sleep(DIRECTORY_ANNOUNCE_INTERVAL * 2)

    async def _announce(self):
        """Announce our node to all known directory nodes."""
        if not self.tor or not self.tor.onion_address:
            return

        announcement = {
            "command": "directory_announce",
            "fingerprint": self.profile["fingerprint"],
            "name": self.profile.get("name", ""),
            "onion_address": self.tor.onion_address,
            "verify_key": self.profile.get("verify_key", ""),
            "box_public_key": self.profile.get("box_public_key", ""),
            "is_directory_node": 1 if self._is_directory_node else 0,
            "timestamp": int(time.time()),
        }

        # Announce to bootstrap nodes
        for node_addr in DIRECTORY_BOOTSTRAP_NODES:
            if node_addr.endswith(".onion"):
                resp = await self.tor.send_to_onion(
                    node_addr, "directory_announce", announcement
                )
                if resp and resp.get("status") == "ok":
                    logger.info("Announced to bootstrap node %s", node_addr[:16])

                    # Save/update the bootstrap node as a directory peer
                    self.storage.save_tor_peer({
                        "fingerprint": resp.get("fingerprint", node_addr[:16]),
                        "onion_address": node_addr,
                        "is_directory_node": 1,
                    })

        # Announce to known directory nodes from DB
        for node in self.storage.get_directory_nodes():
            onion = node.get("onion_address", "")
            if onion and onion not in DIRECTORY_BOOTSTRAP_NODES:
                resp = await self.tor.send_to_onion(
                    onion, "directory_announce", announcement
                )
                if resp and resp.get("status") == "ok":
                    logger.debug("Announced to directory node %s", onion[:16])

    async def _discover_peers(self):
        """Query directory nodes to discover new peers."""
        if not self.tor:
            return

        # Query bootstrap nodes
        for node_addr in DIRECTORY_BOOTSTRAP_NODES:
            if node_addr.endswith(".onion"):
                await self._query_directory(node_addr)

        # Query known directory nodes
        for node in self.storage.get_directory_nodes():
            onion = node.get("onion_address", "")
            if onion and onion not in DIRECTORY_BOOTSTRAP_NODES:
                await self._query_directory(onion)

    async def _query_directory(self, directory_onion: str):
        """Query a single directory node for its peer list."""
        try:
            resp = await self.tor.send_to_onion(
                directory_onion, "directory_query", {
                    "fingerprint": self.profile["fingerprint"],
                    "max_peers": 50,
                }
            )

            if not resp or resp.get("status") != "ok":
                return

            peers = resp.get("peers", [])
            for peer_info in peers:
                fp = peer_info.get("fingerprint", "")
                onion = peer_info.get("onion_address", "")
                if fp and onion and fp != self.profile["fingerprint"]:
                    self.storage.save_tor_peer({
                        "fingerprint": fp,
                        "onion_address": onion,
                        "name": peer_info.get("name", ""),
                        "verify_key": peer_info.get("verify_key", ""),
                        "box_public_key": peer_info.get("box_public_key", ""),
                        "is_directory_node": peer_info.get("is_directory_node", 0),
                    })

            if peers:
                logger.info("Discovered %d peers from %s", len(peers), directory_onion[:16])

        except Exception as e:
            logger.debug("Directory query to %s failed: %s", directory_onion[:16], e)

    async def handle_announce(self, request: dict) -> dict:
        """Handle an incoming directory announcement (if we are a directory node)."""
        if not self._is_directory_node:
            return {"status": "error", "message": "Not a directory node"}

        fp = request.get("fingerprint", "")
        onion = request.get("onion_address", "")

        if not fp or not onion:
            return {"status": "error", "message": "Missing fingerprint or onion_address"}

        self.storage.save_tor_peer({
            "fingerprint": fp,
            "onion_address": onion,
            "name": request.get("name", ""),
            "verify_key": request.get("verify_key", ""),
            "box_public_key": request.get("box_public_key", ""),
            "is_directory_node": request.get("is_directory_node", 0),
            "last_announced": int(time.time()),
        })

        logger.info("Directory: registered %s at %s", fp[:8], onion[:16])

        return {
            "status": "ok",
            "fingerprint": self.profile["fingerprint"],
        }

    async def handle_query(self, request: dict) -> dict:
        """Handle an incoming directory query (if we are a directory node)."""
        if not self._is_directory_node:
            return {"status": "error", "message": "Not a directory node"}

        max_peers = min(request.get("max_peers", 50), 100)
        requester_fp = request.get("fingerprint", "")

        active_peers = self.storage.get_active_tor_peers(max_age=7200)

        # Filter out the requester
        peers = [
            {
                "fingerprint": p["fingerprint"],
                "onion_address": p["onion_address"],
                "name": p.get("name", ""),
                "verify_key": p.get("verify_key", ""),
                "box_public_key": p.get("box_public_key", ""),
                "is_directory_node": p.get("is_directory_node", 0),
            }
            for p in active_peers
            if p["fingerprint"] != requester_fp
        ][:max_peers]

        return {
            "status": "ok",
            "peers": peers,
            "total": len(active_peers),
        }

    async def gossip_peers(self, peer_onion: str):
        """Share our peer list with another node (gossip protocol)."""
        if not self.tor:
            return

        my_peers = self.storage.get_active_tor_peers(max_age=3600)
        peer_list = [
            {
                "fingerprint": p["fingerprint"],
                "onion_address": p["onion_address"],
                "name": p.get("name", ""),
            }
            for p in my_peers[:20]
        ]

        try:
            await self.tor.send_to_onion(
                peer_onion, "peer_gossip", {
                    "fingerprint": self.profile["fingerprint"],
                    "peers": peer_list,
                }
            )
        except Exception as e:
            logger.debug("Gossip to %s failed: %s", peer_onion[:16], e)

    async def handle_gossip(self, request: dict) -> dict:
        """Handle incoming peer gossip."""
        peers = request.get("peers", [])
        added = 0
        for peer_info in peers:
            fp = peer_info.get("fingerprint", "")
            onion = peer_info.get("onion_address", "")
            if fp and onion and fp != self.profile["fingerprint"]:
                existing = self.storage.get_tor_peer(fp)
                if not existing:
                    self.storage.save_tor_peer({
                        "fingerprint": fp,
                        "onion_address": onion,
                        "name": peer_info.get("name", ""),
                    })
                    added += 1

        return {"status": "ok", "added": added}
