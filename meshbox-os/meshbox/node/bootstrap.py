"""
Bootstrap — Connects to seed nodes and joins the network.

The bootstrap process:
1. Connect to hardcoded seed .onion addresses
2. Perform SANP handshake with each seed
3. Request PEER_LIST from seeds
4. Connect to the best discovered peers (up to max_peers)
5. Announce ourselves via GOSSIP
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

from meshbox.crypto.node_identity import NodeIdentity
from meshbox.sanp.protocol import (
    MessageType,
    SANPFrame,
    SANPHandshake,
    read_frame,
    write_frame,
)
from meshbox.sanp.peer_manager import PeerManager
from meshbox.tor_service.tor_manager import TorManager

logger = logging.getLogger("meshbox.node.bootstrap")

# Hardcoded seed nodes — replace with real .onion addresses
DEFAULT_SEEDS: list[str] = [
    # "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.onion:7777",
]


async def bootstrap_network(
    identity: NodeIdentity,
    tor: TorManager,
    peer_manager: PeerManager,
    seeds: Optional[list[str]] = None,
    sanp_port: int = 7777,
) -> int:
    """Connect to seed nodes and populate the peer manager.

    Returns the number of peers successfully connected.
    """
    seed_list = seeds or DEFAULT_SEEDS
    if not seed_list:
        logger.warning("No bootstrap seeds configured — running in isolated mode")
        return 0

    connected = 0

    for seed in seed_list:
        if ":" in seed:
            onion_addr, port_str = seed.rsplit(":", 1)
            port = int(port_str)
        else:
            onion_addr = seed
            port = sanp_port

        if not peer_manager.can_accept_peer:
            logger.info("Max peers reached, stopping bootstrap")
            break

        try:
            count = await _connect_to_seed(
                identity, tor, peer_manager, onion_addr, port
            )
            connected += count
        except Exception as exc:
            logger.warning("Bootstrap to %s failed: %s", onion_addr[:20], exc)

    logger.info("Bootstrap complete — %d peers connected", connected)
    return connected


async def _connect_to_seed(
    identity: NodeIdentity,
    tor: TorManager,
    peer_manager: PeerManager,
    onion_addr: str,
    port: int,
) -> int:
    """Connect to a single seed and exchange peers.  Returns peers added."""
    logger.info("Connecting to seed %s:%d …", onion_addr[:20], port)

    reader, writer = await tor.open_connection(onion_addr, port, timeout=60)

    try:
        # Perform handshake
        handshake = SANPHandshake(identity)
        hello = handshake.create_hello()
        await write_frame(writer, hello)

        ack_frame = await asyncio.wait_for(read_frame(reader), timeout=30)
        if ack_frame.msg_type != MessageType.HELLO_ACK:
            raise ValueError(f"Expected HELLO_ACK, got 0x{ack_frame.msg_type:02x}")

        session_key = handshake.process_hello_ack(ack_frame)
        peer_node_id = handshake.peer_node_id

        # Register the seed as a peer
        peer_manager.add_peer(
            node_id=peer_node_id,
            onion_address=onion_addr,
            pubkey_ed25519=handshake.peer_pubkey_ed25519 or b"",
            pubkey_x25519=handshake.peer_pubkey_x25519 or b"",
        )
        peer_manager.mark_connected(peer_node_id)

        # Request peer list
        req = SANPFrame.make(MessageType.PEER_REQUEST)
        req.sign(identity.signing_key)
        await write_frame(writer, req)

        # Read PEER_LIST response
        resp = await asyncio.wait_for(read_frame(reader), timeout=30)
        peers_added = 0
        if resp.msg_type == MessageType.PEER_LIST and resp.payload:
            peers_added = peer_manager.import_peer_list(resp.payload)
            logger.info("Received %d new peers from seed %s", peers_added, onion_addr[:20])

        return 1 + peers_added  # the seed itself + discovered peers

    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def announce_self(
    identity: NodeIdentity,
    tor: TorManager,
    gossip_publish,
) -> None:
    """Announce our presence to the network via gossip."""
    pub = identity.export_public()
    onion = tor.get_onion_address()
    if not onion:
        return

    await gossip_publish(
        "peer_announce",
        {
            b"node_id": pub["node_id"].encode(),
            b"onion_address": onion.encode(),
            b"pubkey_ed25519": bytes.fromhex(pub["pubkey_ed25519"]),
            b"pubkey_x25519": bytes.fromhex(pub["pubkey_x25519"]),
        },
    )
    logger.info("Announced self to network via gossip")
