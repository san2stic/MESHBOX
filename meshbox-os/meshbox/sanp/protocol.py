"""
SANP Protocol — Frame serialisation, message types, and handshake.

SANP (SAN Adaptive Network Protocol) is a binary P2P protocol serialised with
MessagePack, running over TCP via Tor hidden services.

Frame layout (on the wire):
┌──────────┬────────┬──────────┬──────────┬────────────────────────┐
│ VERSION  │  TYPE  │  MSG_ID  │ PAYLOAD  │     SIGNATURE          │
│ 1 byte   │ 1 byte │ 8 bytes  │ N bytes  │     64 bytes (Ed25519) │
└──────────┴────────┴──────────┴──────────┴────────────────────────┘

The entire frame (including the variable-length payload) is serialised as a
single MessagePack object and prefixed with a 4-byte big-endian length header
when sent over the wire so the receiver can read complete frames.
"""

from __future__ import annotations

import os
import struct
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Optional

import msgpack
import nacl.encoding
import nacl.public
import nacl.signing


# ---------------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------------

SANP_VERSION: int = 1
FRAME_HEADER_LEN: int = 4  # uint32 length prefix
SIGNATURE_LEN: int = 64
MSG_ID_LEN: int = 8
MAX_FRAME_SIZE: int = 10 * 1024 * 1024  # 10 MiB safety limit


class MessageType(IntEnum):
    """SANP frame type codes."""

    HELLO = 0x01
    HELLO_ACK = 0x02
    PING = 0x03
    PONG = 0x04
    PEER_LIST = 0x10
    PEER_REQUEST = 0x11
    MESSAGE = 0x20
    MESSAGE_ACK = 0x21
    MSG_EXPIRE = 0x22
    ROUTE = 0x30
    ROUTE_REQ = 0x31
    GOSSIP = 0x40
    SYNC_REQ = 0x50
    SYNC_DATA = 0x51
    ERROR = 0xFF


# ---------------------------------------------------------------------------
# SANPFrame
# ---------------------------------------------------------------------------

@dataclass
class SANPFrame:
    """A single SANP protocol frame.

    Attributes:
        version:   Protocol version (always SANP_VERSION for new frames).
        msg_type:  One of :class:`MessageType`.
        msg_id:    8-byte random message identifier.
        payload:   Arbitrary MessagePack-serialisable data.
        signature: 64-byte Ed25519 signature (set after ``sign``).
    """

    version: int = SANP_VERSION
    msg_type: int = MessageType.PING
    msg_id: bytes = field(default_factory=lambda: os.urandom(MSG_ID_LEN))
    payload: Any = None
    signature: bytes = b""

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def _signable_bytes(self) -> bytes:
        """Return the canonical byte representation used for signing."""
        return msgpack.packb(
            [self.version, self.msg_type, self.msg_id, self.payload],
            use_bin_type=True,
        )

    def sign(self, signing_key: nacl.signing.SigningKey) -> None:
        """Sign this frame with the node's Ed25519 key.  Sets ``self.signature``."""
        data = self._signable_bytes()
        signed = signing_key.sign(data)
        self.signature = signed.signature

    def validate_signature(self, pubkey: bytes) -> bool:
        """Validate the frame signature against *pubkey* (raw 32-byte Ed25519).

        Returns True if valid, False otherwise.
        """
        try:
            vk = nacl.signing.VerifyKey(pubkey)
            vk.verify(self._signable_bytes(), self.signature)
            return True
        except Exception:
            return False

    def to_bytes(self) -> bytes:
        """Serialise to wire format: 4-byte length prefix + MessagePack body."""
        body = msgpack.packb(
            {
                b"v": self.version,
                b"t": self.msg_type,
                b"i": self.msg_id,
                b"p": self.payload,
                b"s": self.signature,
            },
            use_bin_type=True,
        )
        return struct.pack("!I", len(body)) + body

    @classmethod
    def from_bytes(cls, data: bytes) -> SANPFrame:
        """Deserialise from a raw MessagePack body (without the length prefix)."""
        obj = msgpack.unpackb(data, raw=True)
        frame = cls(
            version=obj[b"v"],
            msg_type=obj[b"t"],
            msg_id=obj[b"i"],
            payload=obj[b"p"],
            signature=obj[b"s"],
        )
        return frame

    # ------------------------------------------------------------------
    # Factory helpers
    # ------------------------------------------------------------------

    @classmethod
    def make(cls, msg_type: MessageType, payload: Any = None) -> SANPFrame:
        """Create a new unsigned frame with a fresh msg_id."""
        return cls(
            version=SANP_VERSION,
            msg_type=int(msg_type),
            msg_id=os.urandom(MSG_ID_LEN),
            payload=payload,
        )


# ---------------------------------------------------------------------------
# Async I/O helpers
# ---------------------------------------------------------------------------

async def read_frame(reader: "asyncio.StreamReader") -> SANPFrame:
    """Read a single SANP frame from an asyncio StreamReader."""
    import asyncio

    header = await reader.readexactly(FRAME_HEADER_LEN)
    (length,) = struct.unpack("!I", header)
    if length > MAX_FRAME_SIZE:
        raise ValueError(f"Frame too large: {length} bytes (max {MAX_FRAME_SIZE})")
    body = await reader.readexactly(length)
    return SANPFrame.from_bytes(body)


async def write_frame(
    writer: "asyncio.StreamWriter", frame: SANPFrame
) -> None:
    """Write a SANP frame to an asyncio StreamWriter."""
    writer.write(frame.to_bytes())
    await writer.drain()


# ---------------------------------------------------------------------------
# SANPHandshake
# ---------------------------------------------------------------------------

class SANPHandshake:
    """HELLO / HELLO_ACK handshake with X25519 ephemeral key exchange.

    After a successful handshake both sides share a ``session_key``
    (32 bytes) derived from a DH exchange of ephemeral X25519 keys.
    This provides perfect forward secrecy for the session.
    """

    def __init__(self, identity: "NodeIdentity") -> None:
        from meshbox.crypto.node_identity import NodeIdentity

        self.identity: NodeIdentity = identity
        self._ephemeral_private = nacl.public.PrivateKey.generate()
        self._ephemeral_public = self._ephemeral_private.public_key
        self.session_key: Optional[bytes] = None
        self.peer_node_id: Optional[str] = None
        self.peer_pubkey_ed25519: Optional[bytes] = None
        self.peer_pubkey_x25519: Optional[bytes] = None

    # -- Initiator side ----------------------------------------------------

    def create_hello(self) -> SANPFrame:
        """Build the HELLO frame (sent by the connection initiator)."""
        pub = self.identity.export_public()
        payload = {
            b"node_id": pub["node_id"].encode(),
            b"pubkey_ed25519": bytes.fromhex(pub["pubkey_ed25519"]),
            b"pubkey_x25519": bytes.fromhex(pub["pubkey_x25519"]),
            b"ephemeral_x25519": self._ephemeral_public.encode(
                nacl.encoding.RawEncoder
            ),
            b"timestamp": int(time.time()),
        }
        frame = SANPFrame.make(MessageType.HELLO, payload)
        frame.sign(self.identity.signing_key)
        return frame

    def process_hello_ack(self, frame: SANPFrame) -> bytes:
        """Process HELLO_ACK from responder. Returns the derived session key."""
        p = frame.payload
        self.peer_node_id = p[b"node_id"].decode()
        self.peer_pubkey_ed25519 = p[b"pubkey_ed25519"]
        self.peer_pubkey_x25519 = p[b"pubkey_x25519"]
        peer_ephemeral = nacl.public.PublicKey(p[b"ephemeral_x25519"])

        # Verify signature
        if not frame.validate_signature(self.peer_pubkey_ed25519):
            raise ValueError("Invalid HELLO_ACK signature")

        # Derive session key via DH
        self.session_key = self._derive_session_key(peer_ephemeral)
        return self.session_key

    # -- Responder side ----------------------------------------------------

    def process_hello(self, frame: SANPFrame) -> tuple[SANPFrame, bytes]:
        """Process incoming HELLO, return (HELLO_ACK frame, session_key)."""
        p = frame.payload
        self.peer_node_id = p[b"node_id"].decode()
        self.peer_pubkey_ed25519 = p[b"pubkey_ed25519"]
        self.peer_pubkey_x25519 = p[b"pubkey_x25519"]
        peer_ephemeral = nacl.public.PublicKey(p[b"ephemeral_x25519"])

        # Verify signature
        if not frame.validate_signature(self.peer_pubkey_ed25519):
            raise ValueError("Invalid HELLO signature")

        # Build HELLO_ACK
        pub = self.identity.export_public()
        payload = {
            b"node_id": pub["node_id"].encode(),
            b"pubkey_ed25519": bytes.fromhex(pub["pubkey_ed25519"]),
            b"pubkey_x25519": bytes.fromhex(pub["pubkey_x25519"]),
            b"ephemeral_x25519": self._ephemeral_public.encode(
                nacl.encoding.RawEncoder
            ),
            b"timestamp": int(time.time()),
        }
        ack = SANPFrame.make(MessageType.HELLO_ACK, payload)
        ack.sign(self.identity.signing_key)

        # Derive session key
        self.session_key = self._derive_session_key(peer_ephemeral)
        return ack, self.session_key

    # -- Shared session encryption -----------------------------------------

    def encrypt_session(self, plaintext: bytes) -> bytes:
        """Encrypt data with the session key (XSalsa20-Poly1305)."""
        if self.session_key is None:
            raise RuntimeError("Handshake not completed")
        box = nacl.secret.SecretBox(self.session_key)
        return bytes(box.encrypt(plaintext))

    def decrypt_session(self, ciphertext: bytes) -> bytes:
        """Decrypt data with the session key."""
        if self.session_key is None:
            raise RuntimeError("Handshake not completed")
        import nacl.secret

        box = nacl.secret.SecretBox(self.session_key)
        return bytes(box.decrypt(ciphertext))

    # -- Internal ----------------------------------------------------------

    def _derive_session_key(
        self, peer_ephemeral: nacl.public.PublicKey
    ) -> bytes:
        """X25519 DH + SHA3-256 to derive 32-byte session key."""
        import hashlib

        shared = nacl.bindings.crypto_scalarmult(
            self._ephemeral_private.encode(nacl.encoding.RawEncoder),
            peer_ephemeral.encode(nacl.encoding.RawEncoder),
        )
        return hashlib.sha3_256(shared).digest()
