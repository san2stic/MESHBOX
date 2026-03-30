"""
MeshBox REST API — FastAPI local API server bound to 127.0.0.1.

Exposes node status, peer management, messaging, routing table, gossip, and
health endpoints.  Also serves a WebSocket for real-time log streaming.

The API server is started as an asyncio task by the daemon.
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


class GossipPublishRequest(BaseModel):
    topic: str
    data: dict


class PeerAddRequest(BaseModel):
    onion_address: str


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
        title="MeshBox API",
        version="1.0.0",
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

    # -- Node info ---------------------------------------------------------

    @app.get("/api/v1/node/info")
    async def node_info():
        d = _get_daemon()
        return {
            "node_id": d.identity.node_id if d.identity else None,
            "onion_address": d.tor.get_onion_address() if d.tor else None,
            "version": "1.0.0",
            "uptime": int(time.time() - _start_time),
        }

    @app.get("/api/v1/node/stats")
    async def node_stats():
        d = _get_daemon()
        return {
            "peers_count": d.peer_manager.connected_count if d.peer_manager else 0,
            "total_known_peers": len(d.peer_manager.peers) if d.peer_manager else 0,
            "routes": len(d.router) if d.router else 0,
            "server_connections": d.server.connection_count if d.server else 0,
            "uptime": int(time.time() - _start_time),
        }

    # -- Peers -------------------------------------------------------------

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
        # We don't know the node_id yet — it will be learned during handshake
        # For manual addition, use a placeholder
        return {"status": "queued", "onion_address": req.onion_address}

    # -- Messaging ---------------------------------------------------------

    @app.post("/api/v1/message/send")
    async def send_message(req: SendMessageRequest):
        d = _get_daemon()
        ok = await d.send_message(req.to, req.content.encode("utf-8"))
        if not ok:
            raise HTTPException(502, detail="Could not send message")
        return {"status": "sent", "to": req.to}

    @app.get("/api/v1/messages")
    async def get_messages():
        # Messages are not persisted in this layer — returns placeholder
        return {"messages": []}

    # -- Network topology --------------------------------------------------

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

    # -- Gossip ------------------------------------------------------------

    @app.post("/api/v1/gossip/publish")
    async def gossip_publish(req: GossipPublishRequest):
        d = _get_daemon()
        if not d.gossip:
            raise HTTPException(503)
        msg_id = await d.gossip.publish(req.topic, req.data)
        return {"status": "published", "msg_id": msg_id.hex()}

    # -- Health ------------------------------------------------------------

    @app.get("/api/v1/health")
    async def health():
        d = _get_daemon()
        return {
            "status": "ok",
            "tor": d.tor.is_tor_ready() if d.tor else False,
            "peers": d.peer_manager.connected_count if d.peer_manager else 0,
        }

    # -- WebSocket log stream ----------------------------------------------

    @app.websocket("/ws/logs")
    async def ws_logs(websocket: WebSocket):
        await websocket.accept()
        handler = _WSLogHandler(websocket)
        root_logger = logging.getLogger("meshbox")
        root_logger.addHandler(handler)
        try:
            while True:
                # Keep connection alive — client can send pings
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
