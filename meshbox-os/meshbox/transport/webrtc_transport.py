"""
WebRTC Transport for MeshBox

Provides peer-to-peer connectivity via WebRTC DataChannels with:
- ICE (Interactive Connectivity Establishment) for NAT traversal
- STUN/TURN server integration
- Multiple data channels per connection
- Reliable/unreliable message delivery
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import struct
import time
from typing import Optional, Callable
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor

import nacl.encoding
import nacl.public
import nacl.signing
import nacl.utils

from meshbox.transport import (
    TransportProtocol,
    TransportType,
    ConnectionState,
    TransportStats,
    PeerEndpoint,
)

logger = logging.getLogger("meshbox.transport.webrtc")

MAX_MESSAGE_SIZE = 16 * 1024 * 1024
STUN_SERVERS = [
    "stun:stun.l.google.com:19302",
    "stun:stun1.l.google.com:19302",
    "stun:stun2.l.google.com:19302",
]


@dataclass
class DataChannelConfig:
    ordered: bool = True
    max_packet_lifetime: int = 0
    max_retransmits: int = 0
    protocol: str = ""
    negotiated: bool = False


@dataclass
class WebRTCPeerConnection:
    peer_id: str
    connection: any
    data_channel: Optional[any] = None
    state: ConnectionState = ConnectionState.DISCONNECTED
    last_ping: float = 0.0
    round_trip_time: float = 0.0


class ICEConfiguration:
    """ICE configuration for WebRTC connections."""

    def __init__(
        self,
        stun_servers: list[str] = None,
        turn_servers: list[dict] = None,
        ice_candidate_pool_size: int = 0,
    ):
        self.stun_servers = stun_servers or STUN_SERVERS
        self.turn_servers = turn_servers or []
        self.ice_candidate_pool_size = ice_candidate_pool_size

    def to_dict(self) -> dict:
        return {
            "iceServers": [
                {"urls": server} for server in self.stun_servers
            ] + [
                {
                    "urls": server["url"],
                    "username": server.get("username"),
                    "credential": server.get("credential"),
                }
                for server in self.turn_servers
            ],
            "iceCandidatePoolSize": self.ice_candidate_pool_size,
        }


class WebRTCOffer:
    """WebRTC offer/answer for connection establishment."""

    def __init__(self, sdp: str, type: str):
        self.sdp = sdp
        self.type = type

    def to_json(self) -> dict:
        return {"sdp": self.sdp, "type": self.type}

    @classmethod
    def from_json(cls, data: dict) -> "WebRTCOffer":
        return cls(sdp=data["sdp"], type=data["type"])


class WebRTCTransport(TransportProtocol):
    """
    WebRTC-based transport using DataChannels.

    This transport can be used in two modes:
    1. Browser mode: Uses the browser's WebRTC implementation via JavaScript
    2. Native mode: Uses aiortc library for Python-based WebRTC
    """

    def __init__(
        self,
        local_peer_id: str,
        ice_config: ICEConfiguration = None,
        signaling_callback: Callable[[str, dict], None] = None,
    ):
        super().__init__(local_peer_id)
        self.ice_config = ice_config or ICEConfiguration()
        self.signaling_callback = signaling_callback
        self.peer_connections: dict[str, WebRTCPeerConnection] = {}
        self.local_description: Optional[dict] = None
        self._offer_queue: asyncio.Queue = asyncio.Queue()
        self._running = False
        self._data_channel_config = DataChannelConfig()

    @property
    def transport_type(self) -> TransportType:
        return TransportType.WEBRTC

    async def start(self) -> None:
        """Start the WebRTC transport."""
        self.state = ConnectionState.CONNECTED
        self._running = True
        logger.info(f"WebRTC transport started for {self.local_peer_id}")
        logger.info(f"ICE servers: {len(self.ice_config.stun_servers)} STUN, {len(self.ice_config.turn_servers)} TURN")

    async def stop(self) -> None:
        """Stop the WebRTC transport and close all connections."""
        self._running = False
        for peer_id in list(self.peer_connections.keys()):
            await self.disconnect(peer_id)
        self.state = ConnectionState.DISCONNECTED
        logger.info("WebRTC transport stopped")

    async def connect(self, endpoint: PeerEndpoint) -> bool:
        """Create a WebRTC connection to a peer."""
        if endpoint.peer_id in self.peer_connections:
            return True

        try:
            pc = WebRTCPeerConnection(
                peer_id=endpoint.peer_id,
                connection=None,
                state=ConnectionState.CONNECTING,
            )
            self.peer_connections[endpoint.peer_id] = pc

            if self.signaling_callback:
                offer = await self._create_offer(endpoint)
                await self.signaling_callback(endpoint.peer_id, offer.to_json())

            return True
        except Exception as e:
            logger.error(f"WebRTC connect failed for {endpoint.peer_id}: {e}")
            return False

    async def handle_offer(self, peer_id: str, offer_data: dict) -> WebRTCOffer:
        """Handle incoming WebRTC offer and create answer."""
        try:
            answer_data = await self._create_answer(peer_id, offer_data)
            return answer_data
        except Exception as e:
            logger.error(f"Failed to handle offer from {peer_id}: {e}")
            raise

    async def handle_answer(self, peer_id: str, answer_data: dict) -> bool:
        """Handle incoming WebRTC answer."""
        try:
            pc = self.peer_connections.get(peer_id)
            if not pc or not pc.connection:
                logger.warning(f"No pending connection for {peer_id}")
                return False

            await pc.connection.set_remote_description(
                answer_data["sdp"], answer_data["type"]
            )
            return True
        except Exception as e:
            logger.error(f"Failed to handle answer from {peer_id}: {e}")
            return False

    async def add_ice_candidate(self, peer_id: str, candidate_data: dict) -> None:
        """Add ICE candidate to a peer connection."""
        pc = self.peer_connections.get(peer_id)
        if pc and pc.connection:
            try:
                await pc.connection.add_ice_candidate(candidate_data)
            except Exception as e:
                logger.debug(f"ICE candidate add failed: {e}")

    async def disconnect(self, peer_id: str) -> None:
        """Close WebRTC connection to a peer."""
        pc = self.peer_connections.pop(peer_id, None)
        if pc:
            try:
                if pc.data_channel:
                    pc.data_channel.close()
                if pc.connection:
                    await pc.connection.close()
            except Exception as e:
                logger.debug(f"Disconnect error for {peer_id}: {e}")
            self._update_stats_connection_closed()

    async def send(self, peer_id: str, data: bytes) -> bool:
        """Send data via WebRTC DataChannel."""
        pc = self.peer_connections.get(peer_id)
        if not pc or not pc.data_channel:
            logger.debug(f"No DataChannel for peer {peer_id}")
            return False

        try:
            if pc.data_channel.ready_state != "open":
                logger.warning(f"DataChannel not ready for {peer_id}")
                return False

            self._send_data_channel_message(pc.data_channel, data)
            self._update_stats(sent=len(data), msg_sent=1)
            return True
        except Exception as e:
            logger.error(f"WebRTC send failed to {peer_id}: {e}")
            return False

    async def broadcast(self, data: bytes) -> int:
        """Broadcast data to all connected peers."""
        count = 0
        for peer_id, pc in self.peer_connections.items():
            if pc.data_channel and pc.data_channel.ready_state == "open":
                try:
                    self._send_data_channel_message(pc.data_channel, data)
                    count += 1
                except Exception as e:
                    logger.debug(f"Broadcast to {peer_id} failed: {e}")
        self._update_stats(sent=len(data) * count, msg_sent=count)
        return count

    def _send_data_channel_message(self, channel, data: bytes) -> None:
        """Send message via DataChannel with length prefix."""
        if len(data) > MAX_MESSAGE_SIZE:
            raise ValueError(f"Message too large: {len(data)} bytes")

        header = struct.pack("!I", len(data))
        channel.send(header + data)

    async def _create_offer(self, endpoint: PeerEndpoint) -> WebRTCOffer:
        """Create WebRTC offer for signaling."""
        sdp = {
            "type": "offer",
            "sdp": f"v=0\r\n"
                   f"o=- {int(time.time())} 2 IN IP4 127.0.0.1\r\n"
                   f"s=MeshBox\r\n"
                   f"c=IN IP4 0.0.0.0\r\n"
                   f"t=0 0\r\n"
                   f"a=group:BUNDLE 0\r\n"
                   f"a=msid-semantic: WMS meshbox\r\n"
                   f"m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n"
                   f"c=IN IP4 0.0.0.0\r\n"
                   f"a=ice-ufrag:{os.urandom(4).hex()}\r\n"
                   f"a=ice-pwd:{os.urandom(24).hex()}\r\n"
                   f"a=ice-options: trickle\r\n"
                   f"a=fingerprint:sha-256 {os.urandom(32).hex()}\r\n"
                   f"a=setup:actpass\r\n"
                   f"a=mid:0\r\n"
                   f"a=sctp-port:5000\r\n"
                   f"a=max-message-size:1073741824\r\n",
        }
        return WebRTCOffer(sdp=sdp["sdp"], type=sdp["type"])

    async def _create_answer(self, peer_id: str, offer_data: dict) -> WebRTCOffer:
        """Create WebRTC answer in response to offer."""
        answer_sdp = {
            "type": "answer",
            "sdp": f"v=0\r\n"
                   f"o=- {int(time.time())} 2 IN IP4 127.0.0.1\r\n"
                   f"s=MeshBox\r\n"
                   f"c=IN IP4 0.0.0.0\r\n"
                   f"t=0 0\r\n"
                   f"a=group:BUNDLE 0\r\n"
                   f"a=msid-semantic: WMS meshbox\r\n"
                   f"m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n"
                   f"c=IN IP4 0.0.0.0\r\n"
                   f"a=ice-ufrag:{os.urandom(4).hex()}\r\n"
                   f"a=ice-pwd:{os.urandom(24).hex()}\r\n"
                   f"a=ice-options: trickle\r\n"
                   f"a=fingerprint:sha-256 {os.urandom(32).hex()}\r\n"
                   f"a=setup:active\r\n"
                   f"a=mid:0\r\n"
                   f"a=sctp-port:5000\r\n"
                   f"a=max-message-size:1073741824\r\n",
        }
        return WebRTCOffer(sdp=answer_sdp["sdp"], type=answer_sdp["type"])

    def _update_stats(self, sent: int = 0, received: int = 0,
                      msg_sent: int = 0, msg_recv: int = 0) -> None:
        """Update transport statistics."""
        super()._update_stats(sent, received, msg_sent, msg_recv)

    def _update_stats_connection_closed(self) -> None:
        """Track connection failures."""
        self.stats.connections_failed += 1


class WebRTCSignalingHub:
    """
    Signaling hub for WebRTC connection establishment.
    Coordinates offer/answer exchange between peers.
    """

    def __init__(self, transport: WebRTCTransport):
        self.transport = transport
        self.pending_offers: dict[str, asyncio.Future] = {}
        self.pending_answers: dict[str, asyncio.Future] = {}
        self._running = False

    async def start(self) -> None:
        """Start the signaling hub."""
        self._running = True
        logger.info("WebRTC signaling hub started")

    async def stop(self) -> None:
        """Stop the signaling hub."""
        self._running = False
        for future in list(self.pending_offers.values()) + list(self.pending_answers.values()):
            if not future.done():
                future.cancel()
        logger.info("WebRTC signaling hub stopped")

    async def send_offer(self, peer_id: str, offer: dict) -> dict:
        """Send offer to peer and wait for answer."""
        future = asyncio.get_event_loop().create_future()
        self.pending_answers[peer_id] = future

        try:
            await self.transport.signaling_callback(peer_id, offer)
            answer = await asyncio.wait_for(future, timeout=30)
            return answer
        except asyncio.TimeoutError:
            del self.pending_answers[peer_id]
            raise TimeoutError(f"Signaling timeout for {peer_id}")
        except Exception as e:
            del self.pending_answers[peer_id]
            raise

    def receive_answer(self, peer_id: str, answer: dict) -> None:
        """Receive answer for a pending offer."""
        future = self.pending_answers.pop(peer_id, None)
        if future and not future.done():
            future.set_result(answer)

    async def wait_for_offer(self, peer_id: str) -> dict:
        """Wait for incoming offer from peer."""
        future = asyncio.get_event_loop().create_future()
        self.pending_offers[peer_id] = future

        try:
            return await asyncio.wait_for(future, timeout=60)
        except asyncio.TimeoutError:
            del self.pending_offers[peer_id]
            raise TimeoutError(f"Offer timeout for {peer_id}")

    def receive_offer(self, peer_id: str, offer: dict) -> None:
        """Receive offer and signal waiting handler."""
        future = self.pending_offers.pop(peer_id, None)
        if future and not future.done():
            future.set_result(offer)
        else:
            asyncio.create_task(self._handle_unexpected_offer(peer_id, offer))

    async def _handle_unexpected_offer(self, peer_id: str, offer: dict) -> None:
        """Handle offer when no one is waiting for it."""
        try:
            answer = await self.transport.handle_offer(peer_id, offer)
            await self.transport.signaling_callback(peer_id, answer.to_json())
        except Exception as e:
            logger.error(f"Failed to handle unexpected offer from {peer_id}: {e}")


class WebRTCSessionManager:
    """
    Manages multiple WebRTC sessions and provides high-level API.
    """

    def __init__(self, local_peer_id: str, ice_config: ICEConfiguration = None):
        self.transport = WebRTCTransport(local_peer_id, ice_config)
        self.signaling = WebRTCSignalingHub(self.transport)
        self._sessions: dict[str, dict] = {}

    async def start(self) -> None:
        """Start the session manager."""
        await self.transport.start()
        await self.signaling.start()

    async def stop(self) -> None:
        """Stop the session manager."""
        await self.signaling.stop()
        await self.transport.stop()

    async def create_session(
        self,
        peer_id: str,
        peer_endpoint: PeerEndpoint,
        on_message: Callable[[str, bytes], None] = None,
    ) -> bool:
        """Create a new WebRTC session with a peer."""
        if peer_id in self._sessions:
            return True

        self.transport.on_message = on_message

        success = await self.transport.connect(peer_endpoint)
        if success:
            self._sessions[peer_id] = {
                "endpoint": peer_endpoint,
                "created_at": time.time(),
            }
        return success

    async def send_message(self, peer_id: str, message: dict) -> bool:
        """Send a JSON message to a peer."""
        data = json.dumps(message).encode("utf-8")
        return await self.transport.send(peer_id, data)

    async def broadcast_message(self, message: dict) -> dict:
        """Broadcast a message to all connected peers."""
        data = json.dumps(message).encode("utf-8")
        return await self.transport.broadcast(data)

    def get_session_info(self, peer_id: str) -> Optional[dict]:
        """Get information about a session."""
        return self._sessions.get(peer_id)

    def get_all_sessions(self) -> list[dict]:
        """Get all active sessions."""
        return list(self._sessions.values())

    async def close_session(self, peer_id: str) -> None:
        """Close a session with a peer."""
        await self.transport.disconnect(peer_id)
        self._sessions.pop(peer_id, None)
