"""
MeshBox Network Simulation — Launch N virtual nodes and test connectivity.

This script simulates a local mesh network by creating N MeshBox instances,
each with its own identity.  Since Tor Hidden Services are slow to set up
locally, this simulation uses direct TCP (localhost) connections instead of
Tor, while still exercising the full SANP protocol stack.

Usage::

    python scripts/simulate_network.py --nodes 5

Each node:
- Gets a unique identity (Ed25519 + X25519)
- Runs a SANP server on a unique local port
- Connects to other nodes via direct TCP
- Exchanges PEER_LIST messages
- Sends test messages between random pairs
- Displays the resulting network topology
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import random
import shutil
import sys
import tempfile
import time
from pathlib import Path

# Ensure the project root is on the path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from meshbox.crypto.node_identity import NodeIdentity
from meshbox.sanp.gossip import GossipEngine
from meshbox.sanp.peer_manager import PeerManager
from meshbox.sanp.protocol import (
    MessageType,
    SANPFrame,
    SANPHandshake,
    read_frame,
    write_frame,
)
from meshbox.sanp.router import SANPRouter
from meshbox.node.sanp_server import SANPServer


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("simulation")


class SimNode:
    """A simulated MeshBox node running on localhost."""

    def __init__(self, index: int, base_port: int, data_dir: Path) -> None:
        self.index = index
        self.port = base_port + index
        self.data_dir = data_dir / f"node_{index}"
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.identity = NodeIdentity.generate()
        self.identity.save(self.data_dir)

        self.peer_manager = PeerManager(self.identity.node_id, max_peers=20)
        self.router = SANPRouter(self.identity.node_id)
        self.gossip = GossipEngine(self.identity.node_id, fanout=3)

        self.server = SANPServer(
            self.identity,
            bind_host="127.0.0.1",
            bind_port=self.port,
        )

        # Wire up handlers
        self.server.on(MessageType.PEER_REQUEST, self._handle_peer_request)
        self.server.on(MessageType.PEER_LIST, self._handle_peer_list)
        self.server.on(MessageType.MESSAGE, self._handle_message)
        self.server.on(MessageType.GOSSIP, self._handle_gossip)
        self.server.on(MessageType.HELLO, self._handle_hello)
        self.server.on(MessageType.ERROR, self._handle_disconnect)

        self.messages_received: list[dict] = []

    async def start(self) -> None:
        await self.server.start()
        logger.info(
            "Node %d started — ID: %s  Port: %d",
            self.index,
            self.identity.node_id[:12],
            self.port,
        )

    async def stop(self) -> None:
        await self.server.stop()

    async def connect_to(self, other: SimNode) -> bool:
        """Initiate a SANP connection to another node."""
        try:
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", other.port
            )

            # Handshake
            hs = SANPHandshake(self.identity)
            hello = hs.create_hello()
            await write_frame(writer, hello)

            ack = await asyncio.wait_for(read_frame(reader), timeout=10)
            if ack.msg_type != MessageType.HELLO_ACK:
                writer.close()
                return False

            hs.process_hello_ack(ack)

            # Register peer
            self.peer_manager.add_peer(
                node_id=other.identity.node_id,
                onion_address=f"127.0.0.1:{other.port}",
                pubkey_ed25519=other.identity.verify_key.encode(),
                pubkey_x25519=other.identity.box_public.encode(),
            )
            self.peer_manager.mark_connected(other.identity.node_id)

            # Add route
            self.router.add_route(
                other.identity.node_id,
                f"127.0.0.1:{other.port}",
                other.identity.node_id,
                hops=1,
            )

            writer.close()
            await writer.wait_closed()
            return True
        except Exception as exc:
            logger.warning(
                "Node %d → Node %d connection failed: %s",
                self.index,
                other.index,
                exc,
            )
            return False

    async def send_test_message(self, other: SimNode, content: str) -> bool:
        """Send a test message to another node."""
        try:
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", other.port
            )

            # Handshake
            hs = SANPHandshake(self.identity)
            hello = hs.create_hello()
            await write_frame(writer, hello)
            ack = await asyncio.wait_for(read_frame(reader), timeout=10)
            if ack.msg_type != MessageType.HELLO_ACK:
                writer.close()
                return False
            hs.process_hello_ack(ack)

            # Send encrypted message
            encrypted = self.identity.encrypt_for_peer(
                content.encode(), other.identity.box_public.encode()
            )
            msg = SANPFrame.make(MessageType.MESSAGE, encrypted)
            msg.sign(self.identity.signing_key)
            await write_frame(writer, msg)

            # Wait for ACK
            resp = await asyncio.wait_for(read_frame(reader), timeout=10)
            writer.close()
            await writer.wait_closed()
            return resp.msg_type == MessageType.MESSAGE_ACK
        except Exception as exc:
            logger.warning("Message send failed: %s", exc)
            return False

    # -- Handlers --

    async def _handle_hello(self, node_id, handshake):
        self.peer_manager.add_peer(
            node_id=node_id,
            onion_address="",
            pubkey_ed25519=handshake.peer_pubkey_ed25519 or b"",
            pubkey_x25519=handshake.peer_pubkey_x25519 or b"",
        )
        self.peer_manager.mark_connected(node_id)

    async def _handle_peer_request(self, node_id, frame):
        peers = self.peer_manager.export_peer_list()
        resp = SANPFrame.make(MessageType.PEER_LIST, peers)
        resp.sign(self.identity.signing_key)
        return resp

    async def _handle_peer_list(self, node_id, frame):
        if frame.payload:
            self.peer_manager.import_peer_list(frame.payload)

    async def _handle_message(self, node_id, frame):
        try:
            plaintext = self.identity.decrypt_from_peer(frame.payload)
            self.messages_received.append(
                {"from": node_id[:12], "content": plaintext.decode()}
            )
            logger.info(
                "Node %d received message from %s: %s",
                self.index,
                node_id[:12],
                plaintext.decode()[:50],
            )
        except Exception as exc:
            logger.warning("Node %d decrypt failed: %s", self.index, exc)

        ack = SANPFrame.make(MessageType.MESSAGE_ACK, frame.msg_id)
        ack.sign(self.identity.signing_key)
        return ack

    async def _handle_gossip(self, node_id, frame):
        if frame.payload:
            await self.gossip.handle_incoming(frame.payload)

    async def _handle_disconnect(self, node_id, payload):
        self.peer_manager.mark_disconnected(node_id)


# ---------------------------------------------------------------------------
# Network simulation
# ---------------------------------------------------------------------------


async def simulate(num_nodes: int = 5, base_port: int = 17700) -> None:
    tmpdir = Path(tempfile.mkdtemp(prefix="meshbox_sim_"))
    logger.info("Simulation data: %s", tmpdir)

    # Create nodes
    nodes: list[SimNode] = []
    for i in range(num_nodes):
        node = SimNode(i, base_port, tmpdir)
        nodes.append(node)

    # Start all servers
    logger.info("Starting %d nodes …", num_nodes)
    for node in nodes:
        await node.start()
    await asyncio.sleep(1)

    # Connect each node to 2-3 random others (mesh topology)
    logger.info("Forming mesh connections …")
    connections = 0
    for node in nodes:
        targets = random.sample(
            [n for n in nodes if n is not node],
            min(3, num_nodes - 1),
        )
        for target in targets:
            ok = await node.connect_to(target)
            if ok:
                connections += 1
    logger.info("Established %d connections", connections)

    # Send test messages between random pairs
    logger.info("Sending test messages …")
    messages_sent = 0
    for _ in range(num_nodes * 2):
        sender, receiver = random.sample(nodes, 2)
        content = f"Hello from Node {sender.index} at {time.time():.0f}"
        ok = await sender.send_test_message(receiver, content)
        if ok:
            messages_sent += 1
    logger.info("Successfully sent %d messages", messages_sent)

    # Wait for all messages to be processed
    await asyncio.sleep(2)

    # Display topology
    print("\n" + "=" * 60)
    print("           MESHBOX NETWORK SIMULATION RESULTS")
    print("=" * 60)

    for node in nodes:
        active = node.peer_manager.connected_count
        routes = len(node.router)
        msgs = len(node.messages_received)
        print(
            f"  Node {node.index} [{node.identity.node_id[:8]}…] "
            f"port={node.port}  peers={active}  routes={routes}  "
            f"msgs_recv={msgs}"
        )

    # Topology matrix
    print("\n  Connection Matrix:")
    header = "       " + "  ".join(f"N{i}" for i in range(num_nodes))
    print(header)
    for node in nodes:
        row = f"  N{node.index}  "
        for other in nodes:
            if other is node:
                row += "  · "
            elif other.identity.node_id in node.peer_manager.peers:
                row += "  ✓ "
            else:
                row += "  · "
        print(row)

    total_msgs = sum(len(n.messages_received) for n in nodes)
    print(f"\n  Total messages delivered: {total_msgs}/{messages_sent}")
    print(f"  Total connections: {connections}")
    print("=" * 60)

    # Cleanup
    for node in nodes:
        await node.stop()

    shutil.rmtree(tmpdir, ignore_errors=True)
    logger.info("Simulation complete — temp dir cleaned")


def main():
    parser = argparse.ArgumentParser(description="MeshBox Network Simulation")
    parser.add_argument(
        "--nodes", "-n", type=int, default=5, help="Number of nodes (default: 5)"
    )
    parser.add_argument(
        "--port", "-p", type=int, default=17700, help="Base port (default: 17700)"
    )
    args = parser.parse_args()
    asyncio.run(simulate(num_nodes=args.nodes, base_port=args.port))


if __name__ == "__main__":
    main()
