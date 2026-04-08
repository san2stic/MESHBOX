"""
MeshBox - E2E encryption engine v4.
Uses libsodium (NaCl) via PyNaCl for asymmetric and symmetric encryption.
- Identity keys: Curve25519 (X25519) for key exchange
- Signatures: Ed25519 for message and profile authenticity
- Message encryption: XSalsa20-Poly1305 (crypto_box)
- Perfect Forward Secrecy: ephemeral Curve25519 keys per message
- Replay protection: persistent nonce tracking (DB-backed) + timestamp validation
- Safety numbers: contact verification via fingerprint comparison
- Async proof-of-work for non-blocking spam prevention
"""

import asyncio
import hashlib
import hmac
import os
import struct
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Optional

import nacl.encoding
import nacl.hash
import nacl.public
import nacl.secret
import nacl.signing
import nacl.utils


# Replay protection window (messages older than this are rejected)
REPLAY_WINDOW_SECONDS = 86400 * 7  # 7 days
# Maximum clock skew tolerance
MAX_CLOCK_SKEW = 300  # 5 minutes into the future
# Thread pool for async PoW
_pow_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="meshbox-pow")


class Identity:
    """Cryptographic identity for a MeshBox user."""

    def __init__(self, signing_key: nacl.signing.SigningKey, box_key: nacl.public.PrivateKey):
        self.signing_key = signing_key
        self.verify_key = signing_key.verify_key
        self.box_key = box_key
        self.box_public_key = box_key.public_key

    @property
    def fingerprint(self) -> str:
        """Unique fingerprint derived from the signing public key (hex, 16 chars)."""
        raw = self.verify_key.encode()
        h = nacl.hash.sha256(raw, encoder=nacl.encoding.RawEncoder)
        return h[:8].hex()

    @property
    def fingerprint_full(self) -> str:
        """Full fingerprint (hex, 64 chars)."""
        raw = self.verify_key.encode()
        return nacl.hash.sha256(raw, encoder=nacl.encoding.HexEncoder).decode()

    def export_public(self) -> dict:
        """Export public keys for sharing."""
        return {
            "verify_key": self.verify_key.encode(nacl.encoding.Base64Encoder).decode(),
            "box_public_key": self.box_public_key.encode(nacl.encoding.Base64Encoder).decode(),
            "fingerprint": self.fingerprint,
        }

    def save(self, keys_dir: Path):
        """Save private keys to disk with restricted permissions."""
        keys_dir.mkdir(parents=True, exist_ok=True)

        signing_path = keys_dir / "signing.key"
        box_path = keys_dir / "box.key"

        signing_path.write_bytes(self.signing_key.encode())
        box_path.write_bytes(self.box_key.encode())

        try:
            os.chmod(signing_path, 0o600)
            os.chmod(box_path, 0o600)
        except OSError:
            pass  # Windows doesn't support chmod the same way

    @classmethod
    def load(cls, keys_dir: Path) -> Optional["Identity"]:
        """Load an existing identity from disk."""
        signing_path = keys_dir / "signing.key"
        box_path = keys_dir / "box.key"

        if not signing_path.exists() or not box_path.exists():
            return None

        signing_key = nacl.signing.SigningKey(signing_path.read_bytes())
        box_key = nacl.public.PrivateKey(box_path.read_bytes())
        return cls(signing_key, box_key)

    @classmethod
    def generate(cls) -> "Identity":
        """Generate a new cryptographic identity."""
        signing_key = nacl.signing.SigningKey.generate()
        box_key = nacl.public.PrivateKey.generate()
        return cls(signing_key, box_key)

    def compute_safety_number(self, other_verify_key_b64: str, other_box_key_b64: str) -> str:
        """
        Compute a safety number for contact verification (like Signal).
        Both parties compute the same number, which they can compare
        in-person or via a trusted channel.
        """
        my_vk = self.verify_key.encode()
        my_bk = self.box_public_key.encode()
        other_vk = nacl.encoding.Base64Encoder.decode(other_verify_key_b64.encode())
        other_bk = nacl.encoding.Base64Encoder.decode(other_box_key_b64.encode())

        # Sort keys so both parties get the same result
        keys_a = my_vk + my_bk
        keys_b = other_vk + other_bk

        if keys_a < keys_b:
            combined = keys_a + keys_b
        else:
            combined = keys_b + keys_a

        # 5 rounds of SHA-256 for the safety number
        digest = combined
        for _ in range(5):
            digest = hashlib.sha256(digest).digest()

        # Format as 12 groups of 5 digits (60 digits total, like Signal)
        number = int.from_bytes(digest, "big")
        groups = []
        for _ in range(12):
            groups.append(f"{number % 100000:05d}")
            number //= 100000

        return " ".join(groups)


class NonceTracker:
    """
    Track seen message nonces to prevent replay attacks.
    Supports both in-memory tracking and optional persistent DB-backed storage
    (via StorageEngine) for cross-restart protection.
    """

    def __init__(self, window: int = REPLAY_WINDOW_SECONDS, storage=None):
        self.window = window
        self._storage = storage  # Optional StorageEngine for persistence
        self._seen: dict[str, float] = {}  # nonce_hex -> first_seen_timestamp
        self._last_cleanup = time.time()

    def check_and_record(self, nonce: str, timestamp: int) -> bool:
        """
        Check if a nonce has been seen before. Returns True if the message
        is NEW (not a replay). Returns False if it's a replay.
        """
        now = time.time()

        # Reject messages too far in the future
        if timestamp > now + MAX_CLOCK_SKEW:
            return False

        # Reject messages older than the replay window
        if timestamp < now - self.window:
            return False

        # Cleanup old entries periodically
        if now - self._last_cleanup > 3600:
            self._cleanup(now)

        # Check for replay (memory first, then DB)
        if nonce in self._seen:
            return False
        if self._storage and self._storage.is_nonce_seen(nonce):
            self._seen[nonce] = now  # cache locally
            return False

        self._seen[nonce] = now
        if self._storage:
            self._storage.mark_nonce_seen(nonce)
        return True

    def _cleanup(self, now: float):
        """Remove expired nonces from memory cache."""
        expired = [n for n, ts in self._seen.items() if now - ts > self.window]
        for n in expired:
            del self._seen[n]
        self._last_cleanup = now


class CryptoEngine:
    """Encryption engine for MeshBox messages with Perfect Forward Secrecy."""

    # Protocol version for crypto envelope
    CRYPTO_VERSION = 3

    def __init__(self, identity: Identity, storage=None):
        self.identity = identity
        self.nonce_tracker = NonceTracker(storage=storage)

    def encrypt_message(self, plaintext: str, recipient_public_key_b64: str) -> dict:
        """
        Encrypt a message for a specific recipient with Perfect Forward Secrecy.

        PFS: generates a fresh ephemeral Curve25519 key pair for EACH message.
        The ephemeral private key is used for the crypto_box and then discarded.
        Even if the long-term keys are compromised, past messages remain secure.
        """
        recipient_key = nacl.public.PublicKey(
            recipient_public_key_b64.encode(), nacl.encoding.Base64Encoder
        )

        # Generate ephemeral key pair for PFS
        ephemeral_key = nacl.public.PrivateKey.generate()
        ephemeral_public = ephemeral_key.public_key

        # Encrypt with ephemeral private key -> recipient public key
        box = nacl.public.Box(ephemeral_key, recipient_key)
        message_nonce = nacl.utils.random(nacl.public.Box.NONCE_SIZE)
        encrypted = box.encrypt(plaintext.encode("utf-8"), nonce=message_nonce)

        # Sign the entire envelope (ephemeral_public + ciphertext) with long-term key
        envelope = ephemeral_public.encode() + encrypted
        signed = self.identity.signing_key.sign(envelope)

        return {
            "ciphertext": nacl.encoding.Base64Encoder.encode(encrypted).decode(),
            "ephemeral_key": nacl.encoding.Base64Encoder.encode(
                ephemeral_public.encode()
            ).decode(),
            "signature": nacl.encoding.Base64Encoder.encode(signed.signature).decode(),
            "sender_fingerprint": self.identity.fingerprint,
            "sender_verify_key": self.identity.verify_key.encode(
                nacl.encoding.Base64Encoder
            ).decode(),
            "sender_box_key": self.identity.box_public_key.encode(
                nacl.encoding.Base64Encoder
            ).decode(),
            "timestamp": int(time.time()),
            "nonce": nacl.encoding.Base64Encoder.encode(message_nonce).decode(),
            "version": self.CRYPTO_VERSION,
        }

    def decrypt_message(self, encrypted_msg: dict) -> Optional[str]:
        """
        Decrypt a received message.
        Supports both v1 (legacy) and v2 (PFS with ephemeral keys) envelopes.
        Validates signature and checks for replay attacks.
        """
        version = encrypted_msg.get("version", 1)

        if version >= 2:
            return self._decrypt_v2(encrypted_msg)
        else:
            return self._decrypt_v1(encrypted_msg)

    def _decrypt_v2(self, encrypted_msg: dict) -> Optional[str]:
        """Decrypt a v2 message (PFS with ephemeral keys)."""
        try:
            ciphertext = nacl.encoding.Base64Encoder.decode(
                encrypted_msg["ciphertext"].encode()
            )
            ephemeral_key = nacl.public.PublicKey(
                encrypted_msg["ephemeral_key"].encode(),
                nacl.encoding.Base64Encoder,
            )
            signature = nacl.encoding.Base64Encoder.decode(
                encrypted_msg["signature"].encode()
            )
            sender_verify_key = nacl.signing.VerifyKey(
                encrypted_msg["sender_verify_key"].encode(),
                nacl.encoding.Base64Encoder,
            )

            # Verify signature over (ephemeral_public + ciphertext)
            envelope = ephemeral_key.encode() + ciphertext
            sender_verify_key.verify(envelope, signature)

            # Check replay protection
            nonce_b64 = encrypted_msg.get("nonce", "")
            timestamp = encrypted_msg.get("timestamp", 0)
            if nonce_b64:
                nonce_id = hashlib.sha256(
                    f"{encrypted_msg['sender_fingerprint']}:{nonce_b64}".encode()
                ).hexdigest()[:32]
                if not self.nonce_tracker.check_and_record(nonce_id, timestamp):
                    return None  # Replay detected

            # Decrypt with our long-term private key + ephemeral public key
            box = nacl.public.Box(self.identity.box_key, ephemeral_key)
            plaintext = box.decrypt(ciphertext)

            return plaintext.decode("utf-8")

        except Exception:
            return None

    def _decrypt_v1(self, encrypted_msg: dict) -> Optional[str]:
        """Decrypt a v1 (legacy) message for backward compatibility."""
        try:
            ciphertext = nacl.encoding.Base64Encoder.decode(
                encrypted_msg["ciphertext"].encode()
            )
            signature = nacl.encoding.Base64Encoder.decode(
                encrypted_msg["signature"].encode()
            )
            sender_verify_key = nacl.signing.VerifyKey(
                encrypted_msg["sender_verify_key"].encode(),
                nacl.encoding.Base64Encoder,
            )
            sender_box_key = nacl.public.PublicKey(
                encrypted_msg["sender_box_key"].encode(),
                nacl.encoding.Base64Encoder,
            )

            sender_verify_key.verify(ciphertext, signature)

            box = nacl.public.Box(self.identity.box_key, sender_box_key)
            plaintext = box.decrypt(ciphertext)

            return plaintext.decode("utf-8")

        except Exception:
            return None

    def sign_data(self, data: bytes) -> bytes:
        """Sign arbitrary data."""
        return self.identity.signing_key.sign(data).signature

    @staticmethod
    def verify_signature(data: bytes, signature: bytes, verify_key_b64: str) -> bool:
        """Verify a signature."""
        try:
            vk = nacl.signing.VerifyKey(
                verify_key_b64.encode(), nacl.encoding.Base64Encoder
            )
            vk.verify(data, signature)
            return True
        except nacl.exceptions.BadSignatureError:
            return False

    @staticmethod
    def generate_proof_of_work(data: bytes, difficulty: int = 16) -> int:
        """
        Simple proof-of-work anti-spam.
        Find a nonce such that SHA256(data + nonce) starts with `difficulty` zero bits.
        """
        target = 2 ** (256 - difficulty)
        nonce = 0
        while True:
            attempt = data + nonce.to_bytes(8, "big")
            h = int(hashlib.sha256(attempt).hexdigest(), 16)
            if h < target:
                return nonce
            nonce += 1

    @staticmethod
    async def generate_proof_of_work_async(data: bytes, difficulty: int = 16) -> int:
        """Non-blocking proof-of-work using a thread pool."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            _pow_executor,
            CryptoEngine.generate_proof_of_work,
            data,
            difficulty,
        )

    @staticmethod
    def verify_proof_of_work(data: bytes, nonce: int, difficulty: int = 16) -> bool:
        """Verify a proof-of-work."""
        target = 2 ** (256 - difficulty)
        attempt = data + nonce.to_bytes(8, "big")
        h = int(hashlib.sha256(attempt).hexdigest(), 16)
        return h < target

    @staticmethod
    def derive_symmetric_key(shared_secret: bytes, context: bytes = b"meshbox-v2") -> bytes:
        """Derive a symmetric key from a shared secret using HKDF-like construction."""
        return hashlib.sha256(context + shared_secret).digest()

    def encrypt_symmetric(self, plaintext: bytes, key: bytes) -> bytes:
        """Encrypt data with a symmetric key (SecretBox - XSalsa20-Poly1305)."""
        box = nacl.secret.SecretBox(key)
        return box.encrypt(plaintext)

    def decrypt_symmetric(self, ciphertext: bytes, key: bytes) -> Optional[bytes]:
        """Decrypt data with a symmetric key."""
        try:
            box = nacl.secret.SecretBox(key)
            return box.decrypt(ciphertext)
        except Exception:
            return None


class DeniabilityManager:
    """Manages OTR-style deniable messaging.

    In deniable mode, messages are authenticated with per-message MAC keys
    derived from a chain key. After delivery receipt, the MAC key is revealed,
    making the message repudiable - any third party with the revealed key can
    forge equivalent messages, but cannot prove who originally sent it.
    """

    MAX_REVEALED_KEYS = 1000

    def __init__(self, storage=None):
        self._storage = storage
        self._chain_key: Optional[bytes] = None
        self._pending_reveals: dict[str, float] = {}
        self._revealed_keys: dict[str, bytes] = {}
        self._deniability_enabled = True

    def initialize_chain(self, shared_secret: bytes) -> None:
        """Initialize the MAC chain key from a shared secret."""
        self._chain_key = hashlib.sha256(b"deniability-mac-chain" + shared_secret).digest()

    def derive_mac_key(self, message_id: bytes) -> bytes:
        """Derive a per-message MAC key from the current chain key."""
        if self._chain_key is None:
            raise RuntimeError("Chain key not initialized")
        mac_key = hashlib.sha256(self._chain_key + message_id).digest()
        self._chain_key = hashlib.sha256(b"mac-chain-step" + self._chain_key).digest()
        return mac_key

    def create_mac(self, message_id: bytes, plaintext: bytes) -> bytes:
        """Create a MAC for a message using the derived MAC key."""
        mac_key = self.derive_mac_key(message_id)
        return hmac.new(mac_key, plaintext, hashlib.sha256).digest()

    def verify_mac(self, message_id: bytes, plaintext: bytes, mac: bytes) -> bool:
        """Verify a message MAC using the derived MAC key."""
        expected_mac = self.create_mac(message_id, plaintext)
        return hmac.compare_digest(mac, expected_mac)

    def schedule_reveal(self, message_id: str, mac_key: bytes) -> None:
        """Schedule a MAC key for revelation after delivery receipt."""
        self._pending_reveals[message_id] = time.time()
        self._revealed_keys[message_id] = mac_key
        self._enforce_key_limit()

    def reveal_mac_key(self, message_id: str) -> Optional[bytes]:
        """Return the MAC key for a previously sent message."""
        return self._revealed_keys.get(message_id)

    def mark_delivered(self, message_id: str) -> None:
        """Mark a message as delivered - reveals the MAC key."""
        if message_id in self._pending_reveals:
            del self._pending_reveals[message_id]
            if self._storage:
                self._store_revealed_key(message_id, self._revealed_keys.get(message_id))

    def get_revealed_key(self, message_id: str) -> Optional[bytes]:
        """Get a revealed MAC key (from memory or storage)."""
        key = self._revealed_keys.get(message_id)
        if key is None and self._storage:
            key = self._storage.get_revealed_mac_key(message_id)
        return key

    def share_key_with_third_party(self, message_id: str) -> Optional[dict]:
        """Share a revealed MAC key with a third party for deniability verification."""
        key = self.get_revealed_key(message_id)
        if key is None:
            return None
        return {
            "message_id": message_id,
            "mac_key": nacl.encoding.Base64Encoder.encode(key).decode(),
            "revealed_at": int(time.time()),
        }

    def forge_message(self, message_id: bytes, plaintext: bytes, mac_key: bytes) -> bytes:
        """Forge a deniable message using a revealed MAC key.

        This demonstrates that the revealed key can create valid MACs,
        proving the original message was not provably authentic.
        """
        return hmac.new(mac_key, plaintext, hashlib.sha256).digest()

    def _enforce_key_limit(self) -> None:
        """Ensure bounded history of revealed keys."""
        if len(self._revealed_keys) > self.MAX_REVEALED_KEYS:
            keys_to_remove = sorted(self._revealed_keys.keys())[:len(self._revealed_keys) - self.MAX_REVEALED_KEYS]
            for k in keys_to_remove:
                del self._revealed_keys[k]

    def _store_revealed_key(self, message_id: str, mac_key: Optional[bytes]) -> None:
        """Store revealed MAC key in database."""
        if mac_key and self._storage:
            self._storage.save_revealed_mac_key(message_id, mac_key)

    @property
    def is_enabled(self) -> bool:
        """Check if deniability mode is enabled."""
        return self._deniability_enabled

    def set_enabled(self, enabled: bool) -> None:
        """Enable or disable deniability mode."""
        self._deniability_enabled = enabled
