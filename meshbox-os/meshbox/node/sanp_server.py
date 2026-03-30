"""
SANP Server — Asyncio TCP server that accepts SANP connections over Tor.

For every incoming connection the server performs a handshake, establishes a
session key, then dispatches received frames to the appropriate handler
(messaging, routing, gossip, peer exchange, etc.).
"""

from __future__ import annotations

import asyncio
import logging
import struct
import time
from typing import Any, Callable, Coroutine, Optional

from meshbox.crypto.node_identity import NodeIdentity
from meshbox.sanp.protocol import (
    FRAME_HEADER_LEN,
    MAX_FRAME_SIZE,
    MessageType,
    SANPFrame,
    SANPHandshake,
    read_frame,
    write_frame,
)

logger = logging.getLogger("meshbox.node.server")

# Rate limiting per peer — max frames per minute
MAX_FRAMES_PER_MINUTE = 100


class _PeerSession:
    """State for a single connected peer session."""

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        handshake: SANPHandshake,
    ) -> None:
        self.reader = reader
        self.writer = writer
        self.handshake = handshake
        self.node_id: Optional[str] = None
        self.session_key: Optional[bytes] = None
        self._frame_count = 0
        self._window_start = time.time()

    def check_rate_limit(self) -> bool:
        """Returns True if the peer is within rate limits."""
        now = time.time()
        if now - self._window_start > 60:
            self._frame_count = 0
            self._window_start = now
        self._frame_count += 1
        return self._frame_count <= MAX_FRAMES_PER_MINUTE


class SANPServer:
    """Asyncio TCP server that speaks the SANP protocol.

    Binds to 127.0.0.1 on the configured port (Tor hidden service
    forwards external traffic here).
    """

    def __init__(
        self,
        identity: NodeIdentity,
        bind_host: str = "127.0.0.1",
        bind_port: int = 7777,
    ) -> None:
        self.identity = identity
        self.bind_host = bind_host
        self.bind_port = bind_port
        self._server: Optional[asyncio.Server] = None
        self._sessions: dict[str, _PeerSession] = {}  # node_id → session

        # Frame handlers — set by the daemon
        self._handlers: dict[int, Callable[..., Coroutine]] = {}

    # ------------------------------------------------------------------
    # Handler registration
    # ------------------------------------------------------------------

    def on(
        self, msg_type: MessageType, handler: Callable[..., Coroutine]
    ) -> None:
        """Register an async handler for a specific frame type."""
        self._handlers[int(msg_type)] = handler

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_connection,
            self.bind_host,
            self.bind_port,
        )
        addrs = [s.getsockname() for s in self._server.sockets]
        logger.info("SANP server listening on %s", addrs)

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        # Close all peer sessions
        for session in list(self._sessions.values()):
            try:
                session.writer.close()
                await session.writer.wait_closed()
            except Exception:
                pass
        self._sessions.clear()
        logger.info("SANP server stopped")

    # ------------------------------------------------------------------
    # Connection handling
    # ------------------------------------------------------------------

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle a single incoming SANP connection."""
        peer_addr = writer.get_extra_info("peername")
        logger.debug("New connection from %s", peer_addr)

        handshake = SANPHandshake(self.identity)
        session = _PeerSession(reader, writer, handshake)

        try:
            # Read HELLO
            hello_frame = await asyncio.wait_for(read_frame(reader), timeout=30)
            if hello_frame.msg_type != MessageType.HELLO:
                logger.warning("Expected HELLO, got type 0x%02x", hello_frame.msg_type)
                return

            # Process HELLO and send HELLO_ACK
            ack_frame, session_key = handshake.process_hello(hello_frame)
            await write_frame(writer, ack_frame)

            session.node_id = handshake.peer_node_id
            session.session_key = session_key
            self._sessions[session.node_id] = session

            logger.info(
                "Handshake complete with peer %s",
                session.node_id[:12] if session.node_id else "?",
            )

            # Notify handler
            if MessageType.HELLO in self._handlers:
                await self._handlers[MessageType.HELLO](session.node_id, handshake)

            # Frame processing loop
            await self._process_frames(session)

        except asyncio.TimeoutError:
            logger.debug("Connection timed out during handshake")
        except asyncio.IncompleteReadError:
            logger.debug("Peer disconnected")
        except Exception as exc:
            logger.warning("Connection error: %s", exc)
        finally:
            if session.node_id:
                self._sessions.pop(session.node_id, None)
                # Notify disconnect
                if MessageType.ERROR in self._handlers:
                    try:
                        await self._handlers[MessageType.ERROR](
                            session.node_id, {"reason": "disconnected"}
                        )
                    except Exception:
                        pass
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _process_frames(self, session: _PeerSession) -> None:
        """Read and dispatch frames for an established session."""
        while True:
            frame = await read_frame(session.reader)

            # Rate limiting
            if not session.check_rate_limit():
                logger.warning(
                    "Rate limit exceeded for %s",
                    session.node_id[:12] if session.node_id else "?",
                )
                error = SANPFrame.make(
                    MessageType.ERROR, {b"reason": b"rate_limit_exceeded"}
                )
                error.sign(self.identity.signing_key)
                await write_frame(session.writer, error)
                continue

            # Handle built-in types
            if frame.msg_type == MessageType.PING:
                pong = SANPFrame.make(MessageType.PONG, frame.msg_id)
                pong.sign(self.identity.signing_key)
                await write_frame(session.writer, pong)
                continue

            # Dispatch to registered handler
            handler = self._handlers.get(frame.msg_type)
            if handler:
                try:
                    response = await handler(session.node_id, frame)
                    if response is not None and isinstance(response, SANPFrame):
                        await write_frame(session.writer, response)
                except Exception as exc:
                    logger.error(
                        "Handler error for type 0x%02x: %s",
                        frame.msg_type,
                        exc,
                    )
            else:
                logger.debug("No handler for frame type 0x%02x", frame.msg_type)

    # ------------------------------------------------------------------
    # Outbound messaging
    # ------------------------------------------------------------------

    async def send_to_peer(self, node_id: str, frame: SANPFrame) -> bool:
        """Send a frame to an already-connected peer.  Returns True on success."""
        session = self._sessions.get(node_id)
        if not session:
            return False
        try:
            await write_frame(session.writer, frame)
            return True
        except Exception as exc:
            logger.warning("Send to %s failed: %s", node_id[:12], exc)
            return False

    def get_connected_peers(self) -> list[str]:
        """Return node_ids of currently connected peers."""
        return list(self._sessions.keys())

    @property
    def connection_count(self) -> int:
        return len(self._sessions)
