"""
MeshBox Daemon — Main orchestrator that ties all modules together.

Manages the lifecycle of:
- Node identity (load / create)
- Tor hidden service
- SANP server (incoming connections)
- Peer manager + keepalive
- SANP router (distance-vector)
- Gossip engine
- Bootstrap (seed connections)
- REST API server

All I/O is async (asyncio).
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from pathlib import Path
from typing import Optional

from meshbox.crypto.node_identity import NodeIdentity
from meshbox.sanp.gossip import GossipEngine
from meshbox.sanp.peer_manager import PeerManager
from meshbox.sanp.protocol import MessageType, SANPFrame, SANPHandshake
from meshbox.sanp.router import SANPRouter
from meshbox.node.sanp_server import SANPServer
from meshbox.tor_service.tor_manager import TorManager

logger = logging.getLogger("meshbox.node.daemon")


class MeshBoxDaemon:
    """Top-level daemon that orchestrates all MeshBox components."""

    def __init__(
        self,
        data_dir: str | Path = "~/.meshbox",
        sanp_port: int = 7777,
        api_port: int = 8080,
        socks_port: int = 9050,
        control_port: int = 9051,
        max_peers: int = 8,
        min_peers: int = 3,
        gossip_fanout: int = 3,
        bootstrap_seeds: Optional[list[str]] = None,
        passphrase: str = "",
    ) -> None:
        self.data_dir = Path(data_dir).expanduser().resolve()
        self.sanp_port = sanp_port
        self.api_port = api_port
        self.passphrase = passphrase
        self.bootstrap_seeds = bootstrap_seeds or []

        # Components (initialised in start())
        self.identity: Optional[NodeIdentity] = None
        self.tor: Optional[TorManager] = None
        self.server: Optional[SANPServer] = None
        self.peer_manager: Optional[PeerManager] = None
        self.router: Optional[SANPRouter] = None
        self.gossip: Optional[GossipEngine] = None

        self._socks_port = socks_port
        self._control_port = control_port
        self._max_peers = max_peers
        self._min_peers = min_peers
        self._gossip_fanout = gossip_fanout

        self._running = False
        self._tasks: list[asyncio.Task] = []
        self._outbound_connections: dict[str, tuple[asyncio.StreamReader, asyncio.StreamWriter]] = {}

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start all components in the correct order."""
        logger.info("Starting MeshBox daemon …")
        self.data_dir.mkdir(parents=True, exist_ok=True)

        # 1. Load or create identity
        self.identity = self._load_or_create_identity()
        logger.info("Node ID: %s", self.identity.node_id)

        # 2. Start Tor
        self.tor = TorManager(
            data_dir=self.data_dir,
            socks_port=self._socks_port,
            control_port=self._control_port,
            sanp_port=self.sanp_port,
        )
        onion = await self.tor.start()
        logger.info("Onion address: %s", onion)

        # 3. Initialise SANP components
        nid = self.identity.node_id

        self.peer_manager = PeerManager(
            nid, max_peers=self._max_peers, min_peers=self._min_peers
        )
        self.router = SANPRouter(nid)
        self.gossip = GossipEngine(nid, fanout=self._gossip_fanout)

        # Wire gossip callbacks
        self.gossip.set_send_callback(self._gossip_send)
        self.gossip.set_peers_callback(self.peer_manager.get_connected_node_ids)

        # Subscribe to gossip topics
        self.gossip.subscribe("peer_announce", self._on_peer_announce)

        # 4. Start SANP server
        self.server = SANPServer(
            self.identity,
            bind_host="127.0.0.1",
            bind_port=self.sanp_port,
        )
        self._register_handlers()
        await self.server.start()

        # 5. Bootstrap
        from meshbox.node.bootstrap import bootstrap_network, announce_self

        await bootstrap_network(
            self.identity, self.tor, self.peer_manager, self.bootstrap_seeds
        )

        # 6. Announce self via gossip
        await announce_self(self.identity, self.tor, self.gossip.publish)

        # 7. Start background tasks
        self._running = True
        self._tasks = [
            asyncio.create_task(self._keepalive_loop()),
            asyncio.create_task(self._route_broadcast_loop()),
            asyncio.create_task(self._peer_discovery_loop()),
            asyncio.create_task(self._cleanup_loop()),
        ]

        # 8. Start REST API (optional — import only if available)
        try:
            from meshbox.api.rest_api import create_api_task

            api_task = asyncio.create_task(
                create_api_task(self, host="127.0.0.1", port=self.api_port)
            )
            self._tasks.append(api_task)
        except ImportError:
            logger.info("REST API module not available, skipping")

        logger.info("MeshBox daemon started successfully")

    async def stop(self) -> None:
        """Gracefully stop all components."""
        logger.info("Stopping MeshBox daemon …")
        self._running = False

        for task in self._tasks:
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)

        # Close outbound connections
        for nid, (r, w) in self._outbound_connections.items():
            try:
                w.close()
                await w.wait_closed()
            except Exception:
                pass
        self._outbound_connections.clear()

        if self.server:
            await self.server.stop()
        if self.tor:
            await self.tor.stop()

        logger.info("MeshBox daemon stopped")

    # ------------------------------------------------------------------
    # Frame handlers (registered on SANP server)
    # ------------------------------------------------------------------

    def _register_handlers(self) -> None:
        assert self.server is not None
        self.server.on(MessageType.HELLO, self._handle_hello)
        self.server.on(MessageType.PEER_LIST, self._handle_peer_list)
        self.server.on(MessageType.PEER_REQUEST, self._handle_peer_request)
        self.server.on(MessageType.MESSAGE, self._handle_message)
        self.server.on(MessageType.MESSAGE_ACK, self._handle_message_ack)
        self.server.on(MessageType.ROUTE, self._handle_route)
        self.server.on(MessageType.ROUTE_REQ, self._handle_route_req)
        self.server.on(MessageType.GOSSIP, self._handle_gossip)
        self.server.on(MessageType.SYNC_REQ, self._handle_sync_req)
        self.server.on(MessageType.SYNC_DATA, self._handle_sync_data)
        self.server.on(MessageType.ERROR, self._handle_peer_disconnect)

    async def _handle_hello(
        self, node_id: str, handshake: SANPHandshake
    ) -> None:
        """A new peer completed the handshake."""
        self.peer_manager.add_peer(
            node_id=node_id,
            onion_address="",  # filled during bootstrap/peer exchange
            pubkey_ed25519=handshake.peer_pubkey_ed25519 or b"",
            pubkey_x25519=handshake.peer_pubkey_x25519 or b"",
        )
        self.peer_manager.mark_connected(node_id)
        logger.info("Peer connected (inbound): %s", node_id[:12])

    async def _handle_peer_request(
        self, node_id: str, frame: SANPFrame
    ) -> SANPFrame:
        """Respond with our known peers."""
        peers = self.peer_manager.export_peer_list()
        resp = SANPFrame.make(MessageType.PEER_LIST, peers)
        resp.sign(self.identity.signing_key)
        return resp

    async def _handle_peer_list(
        self, node_id: str, frame: SANPFrame
    ) -> None:
        if frame.payload:
            added = self.peer_manager.import_peer_list(frame.payload)
            logger.info("Imported %d peers from %s", added, node_id[:12])

    async def _handle_message(
        self, node_id: str, frame: SANPFrame
    ) -> SANPFrame:
        """Handle an incoming encrypted application message."""
        logger.info("Message received from %s (msg_id=%s)", node_id[:12], frame.msg_id.hex())
        # Decrypt payload
        try:
            decrypted = self.identity.decrypt_from_peer(frame.payload)
            # Emit to local subscribers / store
            logger.info("Decrypted message (%d bytes)", len(decrypted))
        except Exception as exc:
            logger.warning("Failed to decrypt message: %s", exc)

        # Send ACK
        ack = SANPFrame.make(MessageType.MESSAGE_ACK, frame.msg_id)
        ack.sign(self.identity.signing_key)
        return ack

    async def _handle_message_ack(
        self, node_id: str, frame: SANPFrame
    ) -> None:
        logger.debug("ACK from %s for msg %s", node_id[:12], frame.payload.hex() if isinstance(frame.payload, bytes) else "")

    async def _handle_route(
        self, node_id: str, frame: SANPFrame
    ) -> None:
        """Process route announcements from a peer."""
        if frame.payload and isinstance(frame.payload, list):
            peer = self.peer_manager.get_peer(node_id)
            sender_onion = peer.onion_address if peer else ""
            changes = self.router.apply_route_update(
                node_id, sender_onion, frame.payload
            )
            if changes:
                logger.debug("Applied %d route changes from %s", changes, node_id[:12])

    async def _handle_route_req(
        self, node_id: str, frame: SANPFrame
    ) -> SANPFrame:
        """Respond to a route request with our routing table."""
        routes = self.router.export_routes()
        resp = SANPFrame.make(MessageType.ROUTE, routes)
        resp.sign(self.identity.signing_key)
        return resp

    async def _handle_gossip(
        self, node_id: str, frame: SANPFrame
    ) -> None:
        if frame.payload:
            await self.gossip.handle_incoming(frame.payload)

    async def _handle_sync_req(
        self, node_id: str, frame: SANPFrame
    ) -> SANPFrame:
        resp = SANPFrame.make(MessageType.SYNC_DATA, {b"status": b"ok"})
        resp.sign(self.identity.signing_key)
        return resp

    async def _handle_sync_data(
        self, node_id: str, frame: SANPFrame
    ) -> None:
        logger.debug("Sync data from %s", node_id[:12])

    async def _handle_peer_disconnect(
        self, node_id: str, payload: dict
    ) -> None:
        self.peer_manager.mark_disconnected(node_id)
        self.router.invalidate_via(node_id)
        logger.info("Peer disconnected: %s", node_id[:12])

    # ------------------------------------------------------------------
    # Gossip callback
    # ------------------------------------------------------------------

    async def _gossip_send(self, node_id: str, payload: dict) -> None:
        """Send a GOSSIP frame to a specific peer."""
        frame = SANPFrame.make(MessageType.GOSSIP, payload)
        frame.sign(self.identity.signing_key)
        if self.server:
            sent = await self.server.send_to_peer(node_id, frame)
            if not sent:
                # Try outbound connection
                await self._send_outbound(node_id, frame)

    async def _on_peer_announce(self, msg) -> None:
        """Handle a gossip peer announcement."""
        data = msg.data
        if isinstance(data, dict):
            nid = data.get(b"node_id", data.get("node_id", b""))
            if isinstance(nid, bytes):
                nid = nid.decode()
            onion = data.get(b"onion_address", data.get("onion_address", b""))
            if isinstance(onion, bytes):
                onion = onion.decode()
            pk_ed = data.get(b"pubkey_ed25519", data.get("pubkey_ed25519", b""))
            pk_x = data.get(b"pubkey_x25519", data.get("pubkey_x25519", b""))

            self.peer_manager.add_peer(
                node_id=nid,
                onion_address=onion,
                pubkey_ed25519=pk_ed,
                pubkey_x25519=pk_x,
            )
            # Add direct route
            self.router.add_route(nid, onion, nid, hops=1)

    # ------------------------------------------------------------------
    # Outbound connections
    # ------------------------------------------------------------------

    async def _send_outbound(self, node_id: str, frame: SANPFrame) -> bool:
        """Send a frame via an outbound connection to a peer."""
        peer = self.peer_manager.get_peer(node_id)
        if not peer or not peer.onion_address:
            return False

        conn = self._outbound_connections.get(node_id)
        if conn:
            try:
                from meshbox.sanp.protocol import write_frame

                await write_frame(conn[1], frame)
                return True
            except Exception:
                self._outbound_connections.pop(node_id, None)

        # Establish new outbound connection
        try:
            reader, writer = await self.tor.open_connection(
                peer.onion_address, self.sanp_port, timeout=30
            )
            # Handshake
            hs = SANPHandshake(self.identity)
            hello = hs.create_hello()
            from meshbox.sanp.protocol import write_frame as wf, read_frame as rf

            await wf(writer, hello)
            ack = await asyncio.wait_for(rf(reader), timeout=30)
            if ack.msg_type != MessageType.HELLO_ACK:
                writer.close()
                return False
            hs.process_hello_ack(ack)

            self._outbound_connections[node_id] = (reader, writer)
            await wf(writer, frame)
            return True
        except Exception as exc:
            logger.debug("Outbound to %s failed: %s", node_id[:12], exc)
            self.peer_manager.record_failure(node_id)
            return False

    # ------------------------------------------------------------------
    # Messaging API
    # ------------------------------------------------------------------

    async def send_message(
        self, target_node_id: str, plaintext: bytes
    ) -> bool:
        """Send an encrypted message to a target node.

        Returns True if the message was sent (not necessarily delivered).
        """
        peer = self.peer_manager.get_peer(target_node_id)
        if not peer or not peer.pubkey_x25519:
            logger.warning("No public key for %s", target_node_id[:12])
            return False

        encrypted = self.identity.encrypt_for_peer(plaintext, peer.pubkey_x25519)
        frame = SANPFrame.make(MessageType.MESSAGE, encrypted)
        frame.sign(self.identity.signing_key)

        # Try direct
        sent = await self.server.send_to_peer(target_node_id, frame)
        if not sent:
            sent = await self._send_outbound(target_node_id, frame)
        return sent

    # ------------------------------------------------------------------
    # Background tasks
    # ------------------------------------------------------------------

    async def _keepalive_loop(self) -> None:
        """PING/PONG keepalive with connected peers every 60s."""
        while self._running:
            await asyncio.sleep(60)
            for peer in self.peer_manager.get_active_peers():
                ping = SANPFrame.make(MessageType.PING)
                ping.sign(self.identity.signing_key)
                t0 = time.time()
                sent = await self.server.send_to_peer(peer.node_id, ping)
                if sent:
                    latency = (time.time() - t0) * 1000
                    self.peer_manager.record_pong(peer.node_id, latency)
                else:
                    self.peer_manager.record_failure(peer.node_id)

    async def _route_broadcast_loop(self) -> None:
        """Broadcast routing table to peers every 120s."""
        while self._running:
            await asyncio.sleep(120)
            routes = self.router.export_routes()
            if not routes:
                continue
            frame = SANPFrame.make(MessageType.ROUTE, routes)
            frame.sign(self.identity.signing_key)
            for peer in self.peer_manager.get_active_peers():
                await self.server.send_to_peer(peer.node_id, frame)

    async def _peer_discovery_loop(self) -> None:
        """Request more peers if we're below min_peers, every 300s."""
        while self._running:
            await asyncio.sleep(300)
            if self.peer_manager.needs_more_peers:
                for peer in self.peer_manager.get_active_peers():
                    req = SANPFrame.make(MessageType.PEER_REQUEST)
                    req.sign(self.identity.signing_key)
                    await self.server.send_to_peer(peer.node_id, req)

    async def _cleanup_loop(self) -> None:
        """Periodic cleanup of stale peers, expired routes, and gossip cache."""
        while self._running:
            await asyncio.sleep(180)
            self.peer_manager.cleanup_stale()
            self.router.cleanup_expired()
            self.gossip.cleanup()

    # ------------------------------------------------------------------
    # Identity
    # ------------------------------------------------------------------

    def _load_or_create_identity(self) -> NodeIdentity:
        """Load existing identity or generate a fresh one."""
        try:
            identity = NodeIdentity.load(self.data_dir, self.passphrase)
            logger.info("Loaded existing identity: %s", identity.node_id[:16])
        except FileNotFoundError:
            identity = NodeIdentity.generate()
            identity.save(self.data_dir, self.passphrase)
            logger.info("Generated new identity: %s", identity.node_id[:16])
        return identity

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def get_status(self) -> dict:
        """Return a status summary dict for the API."""
        return {
            "node_id": self.identity.node_id if self.identity else None,
            "onion_address": self.tor.get_onion_address() if self.tor else None,
            "running": self._running,
            "tor_ready": self.tor.is_tor_ready() if self.tor else False,
            "peers": self.peer_manager.get_stats() if self.peer_manager else {},
            "routes": len(self.router) if self.router else 0,
            "uptime": 0,  # TODO: track start time
        }
