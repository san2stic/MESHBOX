"""
MeshBox REST API — FastAPI local API server bound to 127.0.0.1.

Full CRUD for all MeshBox features via SANP daemon:
- Node info & status
- Peer management
- Messaging (send, inbox, outbox, read, delete)
- Contacts
- Files
- SOS alerts
- Channels
- Routing & topology
- Gossip
- Health + WebSocket logs

The API server is started as an asyncio task by the daemon.
SANP v5.0.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import TYPE_CHECKING, Optional

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

if TYPE_CHECKING:
    from meshbox.node.meshbox_daemon import MeshBoxDaemon

logger = logging.getLogger("meshbox.api")

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class SendMessageRequest(BaseModel):
    to: str  # target node_id
    content: str
    disappear_after_read: bool = False
    disappear_timer: int = 0


class GossipPublishRequest(BaseModel):
    topic: str
    data: dict


class PeerAddRequest(BaseModel):
    onion_address: str


class SOSRequest(BaseModel):
    message: str
    severity: str = "high"
    latitude: Optional[float] = None
    longitude: Optional[float] = None


class ChannelCreateRequest(BaseModel):
    name: str
    description: str = ""


class ChannelPostRequest(BaseModel):
    content: str


class ContactAddRequest(BaseModel):
    fingerprint: str
    name: str
    verify_key: str
    box_public_key: str
    bio: str = ""


class ProfileUpdateRequest(BaseModel):
    name: Optional[str] = None
    bio: Optional[str] = None


class ProfileCreateRequest(BaseModel):
    name: str
    bio: str = ""


# ---------------------------------------------------------------------------
# API factory
# ---------------------------------------------------------------------------

_daemon: Optional["MeshBoxDaemon"] = None
_start_time: float = 0.0


def create_app(daemon: "MeshBoxDaemon") -> FastAPI:
    """Create the FastAPI application wired to the daemon."""
    global _daemon, _start_time
    _daemon = daemon
    _start_time = time.time()

    app = FastAPI(
        title="MeshBox SANP API",
        version="5.0.0",
        docs_url="/api/docs",
        redoc_url=None,
    )

    # Only allow local connections
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://127.0.0.1:*", "http://localhost:*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Node info ─────────────────────────────────────────────

    @app.get("/api/v1/node/info")
    async def node_info():
        d = _get_daemon()
        return {
            "node_id": d.identity.node_id if d.identity else None,
            "onion_address": d.tor.get_onion_address() if d.tor else None,
            "version": "5.0.0",
            "protocol": "SANP v1",
            "uptime": int(time.time() - _start_time),
            "sanp_port": d.sanp_port,
            "api_port": d.api_port,
        }

    @app.get("/api/v1/node/stats")
    async def node_stats():
        d = _get_daemon()
        storage_stats = d.storage.get_stats() if d.storage else {}
        return {
            "peers_count": d.peer_manager.connected_count if d.peer_manager else 0,
            "total_known_peers": len(d.peer_manager.peers) if d.peer_manager else 0,
            "routes": len(d.router) if d.router else 0,
            "server_connections": d.server.connection_count if d.server else 0,
            "uptime": int(time.time() - _start_time),
            **storage_stats,
        }

    @app.get("/api/v1/node/status")
    async def node_status():
        d = _get_daemon()
        return d.get_status()

    # ── Profile ───────────────────────────────────────────────

    @app.get("/api/v1/profile")
    async def get_profile():
        d = _get_daemon()
        if not d.storage:
            raise HTTPException(503)
        profile = d.storage.get_local_profile()
        if not profile:
            raise HTTPException(404, detail="No profile found")
        return profile

    @app.post("/api/v1/profile")
    async def create_profile(req: ProfileCreateRequest):
        d = _get_daemon()
        if not d.storage or not d.identity:
            raise HTTPException(503)
        pub = d.identity.export_public()
        d.storage.set_setting("profile_name", req.name)
        d.storage.set_setting("profile_bio", req.bio)
        d.storage.save_profile({
            "fingerprint": d.identity.node_id[:16],
            "name": req.name,
            "verify_key": pub["pubkey_ed25519"],
            "box_public_key": pub["pubkey_x25519"],
            "bio": req.bio,
            "is_local": 1,
            "created_at": int(d.identity.created_at),
        })
        return {"status": "created", "fingerprint": d.identity.node_id[:16], "name": req.name}

    @app.put("/api/v1/profile")
    async def update_profile(req: ProfileUpdateRequest):
        d = _get_daemon()
        if not d.storage:
            raise HTTPException(503)
        if req.name:
            d.storage.set_setting("profile_name", req.name)
        if req.bio is not None:
            d.storage.set_setting("profile_bio", req.bio)
        d._save_identity_to_storage()
        return {"status": "updated"}

    # ── Peers ─────────────────────────────────────────────────

    @app.get("/api/v1/peers")
    async def list_peers():
        d = _get_daemon()
        if not d.peer_manager:
            return []
        return [
            {
                "node_id": p.node_id,
                "onion_address": p.onion_address,
                "connected": p.is_connected,
                "latency_ms": p.latency_ms,
                "hops": p.hops,
                "last_seen": p.last_seen,
            }
            for p in d.peer_manager.get_all_peers()
        ]

    @app.get("/api/v1/peers/{node_id}")
    async def get_peer(node_id: str):
        d = _get_daemon()
        if not d.peer_manager:
            raise HTTPException(404)
        peer = d.peer_manager.get_peer(node_id)
        if not peer:
            raise HTTPException(404, detail="Peer not found")
        return {
            "node_id": peer.node_id,
            "onion_address": peer.onion_address,
            "connected": peer.is_connected,
            "latency_ms": peer.latency_ms,
            "hops": peer.hops,
            "last_seen": peer.last_seen,
            "failed_attempts": peer.failed_attempts,
        }

    @app.post("/api/v1/peers/add")
    async def add_peer(req: PeerAddRequest):
        d = _get_daemon()
        if not d.peer_manager:
            raise HTTPException(503)
        return {"status": "queued", "onion_address": req.onion_address}

    # ── Messaging (SANP) ──────────────────────────────────────

    @app.post("/api/v1/message/send")
    async def send_message(req: SendMessageRequest):
        d = _get_daemon()
        result = await d.send_message(
            req.to,
            req.content,
            disappear_after_read=req.disappear_after_read,
            disappear_timer=req.disappear_timer,
        )
        if result.get("status") == "error":
            raise HTTPException(502, detail=result.get("detail", "Could not send"))
        return result

    @app.get("/api/v1/messages/inbox")
    async def get_inbox(limit: int = 50, offset: int = 0, unread: bool = False):
        d = _get_daemon()
        if not d.storage or not d.identity:
            raise HTTPException(503)
        fp = d.identity.node_id[:16]
        messages = d.storage.get_inbox(fp, limit=limit, offset=offset)
        if unread:
            messages = [m for m in messages if not m.get("read")]
        return {"messages": messages, "total": d.storage.get_inbox_count(fp)}

    @app.get("/api/v1/messages/outbox")
    async def get_outbox(limit: int = 50, offset: int = 0):
        d = _get_daemon()
        if not d.storage or not d.identity:
            raise HTTPException(503)
        fp = d.identity.node_id[:16]
        messages = d.storage.get_outbox(fp, limit=limit, offset=offset)
        return {"messages": messages, "total": d.storage.get_outbox_count(fp)}

    @app.get("/api/v1/messages/{message_id}")
    async def read_message(message_id: str):
        d = _get_daemon()
        if not d.storage:
            raise HTTPException(503)
        msg = d.storage.get_message_by_id(message_id)
        if not msg:
            raise HTTPException(404, detail="Message not found")
        d.storage.mark_read(message_id)
        return msg

    @app.delete("/api/v1/messages/{message_id}")
    async def delete_message(message_id: str):
        d = _get_daemon()
        if not d.storage:
            raise HTTPException(503)
        d.storage.delete_message(message_id)
        return {"status": "deleted", "message_id": message_id}

    @app.get("/api/v1/messages/search/{query}")
    async def search_messages(query: str):
        d = _get_daemon()
        if not d.storage or not d.identity:
            raise HTTPException(503)
        fp = d.identity.node_id[:16]
        results = d.storage.search_messages(fp, query)
        return {"results": results}

    # ── Contacts ──────────────────────────────────────────────

    @app.get("/api/v1/contacts")
    async def list_contacts():
        d = _get_daemon()
        if not d.storage:
            raise HTTPException(503)
        profiles = d.storage.get_all_profiles()
        return [p for p in profiles if not p.get("is_local")]

    @app.post("/api/v1/contacts")
    async def add_contact(req: ContactAddRequest):
        d = _get_daemon()
        if not d.storage:
            raise HTTPException(503)
        d.storage.save_profile({
            "fingerprint": req.fingerprint,
            "name": req.name,
            "verify_key": req.verify_key,
            "box_public_key": req.box_public_key,
            "bio": req.bio,
            "is_local": 0,
        })
        return {"status": "added", "fingerprint": req.fingerprint}

    @app.delete("/api/v1/contacts/{fingerprint}")
    async def remove_contact(fingerprint: str):
        d = _get_daemon()
        if not d.storage:
            raise HTTPException(503)
        d.storage.delete_contact(fingerprint)
        return {"status": "removed", "fingerprint": fingerprint}

    # ── SOS Alerts (via SANP gossip) ──────────────────────────

    @app.post("/api/v1/sos")
    async def broadcast_sos(req: SOSRequest):
        d = _get_daemon()
        result = await d.broadcast_sos(
            req.message,
            severity=req.severity,
            latitude=req.latitude,
            longitude=req.longitude,
        )
        return result

    @app.get("/api/v1/sos")
    async def list_sos():
        d = _get_daemon()
        if not d.storage:
            raise HTTPException(503)
        return d.storage.get_active_sos()

    # ── Channels (via SANP gossip) ────────────────────────────

    @app.get("/api/v1/channels")
    async def list_channels():
        d = _get_daemon()
        if not d.storage:
            raise HTTPException(503)
        return d.storage.get_channels()

    @app.post("/api/v1/channels")
    async def create_channel(req: ChannelCreateRequest):
        d = _get_daemon()
        if not d.storage or not d.identity:
            raise HTTPException(503)
        import uuid
        channel = {
            "channel_id": str(uuid.uuid4()),
            "name": req.name,
            "description": req.description,
            "creator_fingerprint": d.identity.node_id[:16],
            "is_public": 1,
        }
        d.storage.create_channel(channel)
        return channel

    @app.get("/api/v1/channels/{channel_id}")
    async def get_channel(channel_id: str):
        d = _get_daemon()
        if not d.storage:
            raise HTTPException(503)
        ch = d.storage.get_channel(channel_id)
        if not ch:
            raise HTTPException(404, detail="Channel not found")
        return ch

    @app.post("/api/v1/channels/{channel_id}/post")
    async def post_to_channel(channel_id: str, req: ChannelPostRequest):
        d = _get_daemon()
        ch = d.storage.get_channel(channel_id) if d.storage else None
        if not ch:
            raise HTTPException(404, detail="Channel not found")
        result = await d.post_to_channel(channel_id, req.content)
        return result

    @app.get("/api/v1/channels/{channel_id}/messages")
    async def channel_messages(channel_id: str, limit: int = 50):
        d = _get_daemon()
        if not d.storage:
            raise HTTPException(503)
        return d.storage.get_channel_messages(channel_id, limit)

    # ── Files ─────────────────────────────────────────────────

    @app.get("/api/v1/files")
    async def list_files():
        d = _get_daemon()
        if not d.storage or not d.identity:
            raise HTTPException(503)
        fp = d.identity.node_id[:16]
        return {
            "my_files": d.storage.get_my_files(fp),
            "received": d.storage.get_files_for_me(fp),
        }

    # ── Network topology ──────────────────────────────────────

    @app.get("/api/v1/network/topology")
    async def network_topology():
        d = _get_daemon()
        if not d.router:
            return {"local_node_id": "", "routes": [], "total": 0}
        return d.router.get_topology()

    @app.get("/api/v1/routing/table")
    async def routing_table():
        d = _get_daemon()
        if not d.router:
            return []
        return d.router.export_routes()

    # ── Gossip ────────────────────────────────────────────────

    @app.post("/api/v1/gossip/publish")
    async def gossip_publish(req: GossipPublishRequest):
        d = _get_daemon()
        if not d.gossip:
            raise HTTPException(503)
        msg_id = await d.gossip.publish(req.topic, req.data)
        return {"status": "published", "msg_id": msg_id.hex()}

    # ── Health ────────────────────────────────────────────────

    @app.get("/api/v1/health")
    async def health():
        d = _get_daemon()
        return {
            "status": "ok",
            "protocol": "SANP v1",
            "tor": d.tor.is_tor_ready() if d.tor else False,
            "peers": d.peer_manager.connected_count if d.peer_manager else 0,
        }

    # ── Trust ─────────────────────────────────────────────────

    @app.get("/api/v1/trust/{fingerprint}")
    async def get_trust(fingerprint: str):
        d = _get_daemon()
        if not d.storage:
            raise HTTPException(503)
        score = d.storage.get_trust_score(fingerprint)
        return {"fingerprint": fingerprint, "score": score}

    # ── Tor peers ─────────────────────────────────────────────

    @app.get("/api/v1/tor/peers")
    async def tor_peers(active: bool = False):
        d = _get_daemon()
        if not d.storage:
            raise HTTPException(503)
        if active:
            return d.storage.get_active_tor_peers()
        return d.storage.get_all_tor_peers()

    # ── WebSocket log stream ──────────────────────────────────

    @app.websocket("/ws/logs")
    async def ws_logs(websocket: WebSocket):
        await websocket.accept()
        handler = _WSLogHandler(websocket)
        root_logger = logging.getLogger("meshbox")
        root_logger.addHandler(handler)
        try:
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            pass
        finally:
            root_logger.removeHandler(handler)

    return app


class _WSLogHandler(logging.Handler):
    """Push log records to a WebSocket."""

    def __init__(self, ws: WebSocket) -> None:
        super().__init__()
        self._ws = ws

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            asyncio.get_event_loop().create_task(self._ws.send_text(msg))
        except Exception:
            pass


def _get_daemon() -> "MeshBoxDaemon":
    if _daemon is None:
        raise HTTPException(503, detail="Daemon not started")
    return _daemon


# ---------------------------------------------------------------------------
# Asyncio task entrypoint (called by daemon)
# ---------------------------------------------------------------------------

async def create_api_task(
    daemon: "MeshBoxDaemon",
    host: str = "127.0.0.1",
    port: int = 8080,
) -> None:
    """Start the API server as an asyncio task."""
    import uvicorn

    app = create_app(daemon)
    config = uvicorn.Config(
        app,
        host=host,
        port=port,
        log_level="warning",
        access_log=False,
    )
    server = uvicorn.Server(config)
    await server.serve()
