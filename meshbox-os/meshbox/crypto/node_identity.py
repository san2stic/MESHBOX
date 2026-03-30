"""
MeshBox Node Identity — Permanent cryptographic identity for mesh nodes.

Provides:
- Ed25519 signing key pair (message signing & verification)
- X25519 key pair (Diffie-Hellman key exchange for E2E encryption)
- node_id = SHA3-256(ed25519_pubkey) — 64 hex chars
- Identity storage encrypted with Argon2id-derived key
- E2E message encryption via X25519 + XSalsa20-Poly1305
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Optional

import nacl.encoding
import nacl.exceptions
import nacl.public
import nacl.secret
import nacl.signing
import nacl.utils
from nacl.pwhash import argon2id


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

IDENTITY_FILE = "identity.json"
IDENTITY_VERSION = 1
ARGON2_OPSLIMIT = argon2id.OPSLIMIT_MODERATE
ARGON2_MEMLIMIT = argon2id.MEMLIMIT_MODERATE
SECRET_KEY_SIZE = nacl.secret.SecretBox.KEY_SIZE  # 32


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derive a symmetric key from a passphrase using Argon2id."""
    return argon2id.kdf(
        SECRET_KEY_SIZE,
        passphrase.encode("utf-8"),
        salt,
        opslimit=ARGON2_OPSLIMIT,
        memlimit=ARGON2_MEMLIMIT,
    )


def _encrypt_blob(data: bytes, passphrase: str) -> dict:
    """Encrypt data with Argon2id-derived key and return JSON-safe dict."""
    salt = nacl.utils.random(16)
    key = _derive_key(passphrase, salt)
    box = nacl.secret.SecretBox(key)
    encrypted = box.encrypt(data)
    return {
        "salt": salt.hex(),
        "ciphertext": encrypted.hex(),
    }


def _decrypt_blob(payload: dict, passphrase: str) -> bytes:
    """Decrypt a payload previously encrypted by _encrypt_blob."""
    salt = bytes.fromhex(payload["salt"])
    ciphertext = bytes.fromhex(payload["ciphertext"])
    key = _derive_key(passphrase, salt)
    box = nacl.secret.SecretBox(key)
    return box.decrypt(ciphertext)


# ---------------------------------------------------------------------------
# NodeIdentity
# ---------------------------------------------------------------------------

class NodeIdentity:
    """Permanent cryptographic identity for a MeshBox node.

    Attributes:
        signing_key: Ed25519 private signing key
        verify_key:  Ed25519 public verification key
        box_private: X25519 private key (Curve25519 DH)
        box_public:  X25519 public key
        node_id:     SHA3-256(ed25519 public key) — 64 hex chars
    """

    def __init__(
        self,
        signing_key: nacl.signing.SigningKey,
        box_private: nacl.public.PrivateKey,
    ) -> None:
        self.signing_key = signing_key
        self.verify_key = signing_key.verify_key
        self.box_private = box_private
        self.box_public = box_private.public_key
        self.node_id = self._compute_node_id()
        self.created_at: float = time.time()

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    @classmethod
    def generate(cls) -> NodeIdentity:
        """Generate a brand-new random identity."""
        signing_key = nacl.signing.SigningKey.generate()
        box_private = nacl.public.PrivateKey.generate()
        identity = cls(signing_key, box_private)
        identity.created_at = time.time()
        return identity

    @classmethod
    def load(
        cls,
        data_dir: str | Path,
        passphrase: str = "",
    ) -> NodeIdentity:
        """Load identity from encrypted file in *data_dir*.

        Raises FileNotFoundError if the identity file does not exist.
        Raises nacl.exceptions.CryptoError if the passphrase is wrong.
        """
        path = Path(data_dir) / IDENTITY_FILE
        with open(path, "r") as fh:
            stored = json.load(fh)

        if stored.get("version") != IDENTITY_VERSION:
            raise ValueError(f"Unsupported identity version: {stored.get('version')}")

        if stored.get("encrypted", False):
            raw = _decrypt_blob(stored["data"], passphrase)
            keys = json.loads(raw)
        else:
            keys = stored["data"]

        signing_key = nacl.signing.SigningKey(
            bytes.fromhex(keys["signing_key_hex"])
        )
        box_private = nacl.public.PrivateKey(
            bytes.fromhex(keys["box_private_hex"])
        )
        identity = cls(signing_key, box_private)
        identity.created_at = stored.get("created_at", time.time())
        return identity

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(
        self,
        data_dir: str | Path,
        passphrase: str = "",
    ) -> Path:
        """Save identity to *data_dir*/identity.json.

        If *passphrase* is provided the key material is encrypted with
        Argon2id.  Otherwise it is stored in plaintext (development only).
        """
        data_dir = Path(data_dir)
        data_dir.mkdir(parents=True, exist_ok=True)

        keys = {
            "signing_key_hex": self.signing_key.encode(
                nacl.encoding.RawEncoder
            ).hex(),
            "box_private_hex": self.box_private.encode(
                nacl.encoding.RawEncoder
            ).hex(),
        }

        if passphrase:
            blob = _encrypt_blob(
                json.dumps(keys).encode("utf-8"), passphrase
            )
            stored = {
                "version": IDENTITY_VERSION,
                "encrypted": True,
                "data": blob,
                "created_at": self.created_at,
                "node_id": self.node_id,
            }
        else:
            stored = {
                "version": IDENTITY_VERSION,
                "encrypted": False,
                "data": keys,
                "created_at": self.created_at,
                "node_id": self.node_id,
            }

        path = data_dir / IDENTITY_FILE
        # Write atomically — temp file then rename
        tmp_path = path.with_suffix(".tmp")
        with open(tmp_path, "w") as fh:
            json.dump(stored, fh, indent=2)

        # Restrict permissions before hardening
        os.chmod(tmp_path, 0o600)
        tmp_path.rename(path)
        return path

    # ------------------------------------------------------------------
    # Signing
    # ------------------------------------------------------------------

    def sign_message(self, data: bytes) -> bytes:
        """Sign *data* with Ed25519 and return the 64-byte signature."""
        signed = self.signing_key.sign(data)
        return signed.signature  # 64 bytes

    @staticmethod
    def verify_message(
        data: bytes,
        signature: bytes,
        pubkey: bytes,
    ) -> bool:
        """Verify an Ed25519 *signature* over *data* with *pubkey*.

        Returns True if valid, False otherwise.
        """
        try:
            verify_key = nacl.signing.VerifyKey(pubkey)
            verify_key.verify(data, signature)
            return True
        except nacl.exceptions.BadSignatureError:
            return False

    # ------------------------------------------------------------------
    # Encryption (X25519 + XSalsa20-Poly1305)
    # ------------------------------------------------------------------

    def encrypt_for_peer(
        self,
        plaintext: bytes,
        peer_pubkey_x25519: bytes,
    ) -> dict:
        """Encrypt *plaintext* for a peer identified by their X25519 public key.

        Uses an ephemeral X25519 key pair so each message has unique keying
        material (perfect forward secrecy at the message level).

        Returns dict with ``ciphertext``, ``nonce``, ``ephemeral_pubkey``
        (all hex-encoded).
        """
        # Ephemeral key pair for PFS
        ephemeral_private = nacl.public.PrivateKey.generate()
        ephemeral_public = ephemeral_private.public_key

        peer_pk = nacl.public.PublicKey(peer_pubkey_x25519)
        box = nacl.public.Box(ephemeral_private, peer_pk)
        encrypted = box.encrypt(plaintext)

        return {
            "ciphertext": encrypted.ciphertext.hex(),
            "nonce": encrypted.nonce.hex(),
            "ephemeral_pubkey": ephemeral_public.encode(
                nacl.encoding.RawEncoder
            ).hex(),
        }

    def decrypt_from_peer(self, payload: dict) -> bytes:
        """Decrypt a message encrypted with :meth:`encrypt_for_peer`.

        *payload* must contain ``ciphertext``, ``nonce``, ``ephemeral_pubkey``
        (hex-encoded).
        """
        ephemeral_pk = nacl.public.PublicKey(
            bytes.fromhex(payload["ephemeral_pubkey"])
        )
        nonce = bytes.fromhex(payload["nonce"])
        ciphertext = bytes.fromhex(payload["ciphertext"])

        box = nacl.public.Box(self.box_private, ephemeral_pk)
        return box.decrypt(ciphertext, nonce)

    # ------------------------------------------------------------------
    # Export / import
    # ------------------------------------------------------------------

    def export_public(self) -> dict:
        """Export public identity data for sharing during bootstrap.

        All values are hex-encoded.
        """
        return {
            "node_id": self.node_id,
            "pubkey_ed25519": self.verify_key.encode(
                nacl.encoding.RawEncoder
            ).hex(),
            "pubkey_x25519": self.box_public.encode(
                nacl.encoding.RawEncoder
            ).hex(),
            "created_at": self.created_at,
        }

    @classmethod
    def from_export(cls, data: dict) -> NodeIdentity:
        """Create a *public-only* view of a remote node.

        NOTE: The resulting object has no private keys and cannot sign or
        decrypt.  Use only for verification/encryption toward a remote node.
        """
        # We build a thin wrapper that exposes only public material.
        return _PublicOnlyIdentity(
            node_id=data["node_id"],
            pubkey_ed25519=bytes.fromhex(data["pubkey_ed25519"]),
            pubkey_x25519=bytes.fromhex(data["pubkey_x25519"]),
            created_at=data.get("created_at", 0),
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _compute_node_id(self) -> str:
        raw_pubkey = self.verify_key.encode(nacl.encoding.RawEncoder)
        return hashlib.sha3_256(raw_pubkey).hexdigest()

    def __repr__(self) -> str:
        return f"<NodeIdentity node_id={self.node_id[:16]}…>"


class _PublicOnlyIdentity:
    """Read-only public view of a remote node's identity."""

    def __init__(
        self,
        node_id: str,
        pubkey_ed25519: bytes,
        pubkey_x25519: bytes,
        created_at: float,
    ) -> None:
        self.node_id = node_id
        self.verify_key = nacl.signing.VerifyKey(pubkey_ed25519)
        self.box_public = nacl.public.PublicKey(pubkey_x25519)
        self.created_at = created_at

        # Sentinels so accidental private-key usage raises immediately
        self.signing_key = None  # type: ignore[assignment]
        self.box_private = None  # type: ignore[assignment]

    def verify_message(self, data: bytes, signature: bytes) -> bool:
        try:
            self.verify_key.verify(data, signature)
            return True
        except nacl.exceptions.BadSignatureError:
            return False

    def __repr__(self) -> str:
        return f"<PublicIdentity node_id={self.node_id[:16]}…>"
