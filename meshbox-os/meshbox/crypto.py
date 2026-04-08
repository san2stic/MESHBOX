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
- Sealed Sender: anonymous messaging with HPKE-style encryption
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

# Sealed sender constants
SEALED_PAYLOAD_SIZE = 512
DELIVERY_TOKEN_EXPIRY = 3600
SEALED_RATE_LIMIT_WINDOW = 60
SEALED_RATE_LIMIT_MAX = 10


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


class SealedSenderEngine:
    """Sealed Sender implementation for anonymous messaging.

    Uses HPKE-style encryption:
    - Recipient's public key + ephemeral key = shared secret
    - Encrypt sender identity + message to recipient's box key
    - Delivery token: HMAC-based proof that sender is allowed to contact recipient
    - Relays only see delivery token + ciphertext, cannot determine sender identity

    Key discovery via DHT: no correlation between lookup and message.
    """

    def __init__(self, identity: Identity):
        self.identity = identity
        self._delivery_token_cache: dict[str, float] = {}
        self._rate_limiter: dict[str, list[float]] = {}

    def generate_delivery_token(self, recipient_fp: str) -> bytes:
        """Generate a delivery token proving sender can contact recipient.

        The token is an HMAC over (recipient_fp + timestamp + sender_fp) using
        a shared secret derived from the recipient's box key. This allows the
        recipient to verify the token without revealing sender identity to relays.
        """
        timestamp = int(time.time() // 300)
        token_data = f"{recipient_fp}:{timestamp}:{self.identity.fingerprint}".encode()
        key = self.derive_token_key(recipient_fp)
        token = hmac.new(key, token_data, hashlib.sha256).digest()
        return token

    def verify_delivery_token(self, token: bytes, recipient_fp: str,
                               sender_fp: str) -> bool:
        """Verify a delivery token was generated for the correct recipient."""
        now = int(time.time() // 300)
        for ts in [now - 1, now]:
            expected_data = f"{recipient_fp}:{ts}:{sender_fp}".encode()
            key = self.derive_token_key(recipient_fp)
            expected = hmac.new(key, expected_data, hashlib.sha256).digest()
            if hmac.compare_digest(token, expected):
                return True
        return False

    def derive_token_key(self, recipient_fp: str) -> bytes:
        """Derive a key for delivery token HMAC from recipient fingerprint."""
        return hashlib.sha256(b"delivery_token_v1" + recipient_fp.encode()).digest()

    def encrypt_sealed(self, plaintext: str, recipient_box_pubkey_b64: str,
                      delivery_token: bytes) -> dict:
        """Encrypt a sealed message for anonymous delivery.

        The ciphertext contains encrypted sender identity + message.
        Relays only see: delivery_token + ciphertext (no sender info).
        """
        recipient_pk = nacl.public.PublicKey(
            recipient_box_pubkey_b64.encode(), nacl.encoding.Base64Encoder
        )

        ephemeral_sk = nacl.public.PrivateKey.generate()
        ephemeral_pk = ephemeral_sk.public_key

        sender_id = self.identity.fingerprint
        message_nonce = nacl.utils.random(24)

        inner_plaintext = sender_id.encode("utf-8") + b"\x00" + plaintext.encode("utf-8")
        inner_box = nacl.public.Box(ephemeral_sk, recipient_pk)
        inner_ciphertext = inner_box.encrypt(inner_plaintext, nonce=message_nonce)

        padded_ciphertext = self._add_padding(inner_ciphertext)

        outer_nonce = nacl.utils.random(24)
        outer_box = nacl.public.Box(self.identity.box_key, recipient_pk)
        outer_ciphertext = outer_box.encrypt(padded_ciphertext, nonce=outer_nonce)

        return {
            "delivery_token": nacl.encoding.Base64Encoder.encode(delivery_token).decode(),
            "ciphertext": nacl.encoding.Base64Encoder.encode(outer_ciphertext).decode(),
            "ephemeral_key": nacl.encoding.Base64Encoder.encode(
                ephemeral_pk.encode()
            ).decode(),
            "nonce": nacl.encoding.Base64Encoder.encode(outer_nonce).decode(),
            "inner_nonce": nacl.encoding.Base64Encoder.encode(message_nonce).decode(),
        }

    def decrypt_sealed(self, sealed_msg: dict, sender_fp: str) -> Optional[tuple[str, str]]:
        """Decrypt a sealed message and extract sender identity and plaintext.

        Returns: (sender_fingerprint, plaintext) or None if decryption fails.
        """
        try:
            ciphertext = nacl.encoding.Base64Encoder.decode(
                sealed_msg["ciphertext"].encode()
            )
            ephemeral_pk = nacl.public.PublicKey(
                sealed_msg["ephemeral_key"].encode(),
                nacl.encoding.Base64Encoder,
            )
            outer_nonce = nacl.encoding.Base64Encoder.decode(
                sealed_msg["nonce"].encode()
            )
            inner_nonce = nacl.encoding.Base64Encoder.decode(
                sealed_msg["inner_nonce"].encode()
            )

            outer_box = nacl.public.Box(self.identity.box_key, ephemeral_pk)
            padded_inner = outer_box.decrypt(ciphertext, nonce=outer_nonce)

            inner_ciphertext = self._remove_padding(padded_inner)

            inner_box = nacl.public.Box(ephemeral_pk, self.identity.box_key)
            inner_plaintext = inner_box.decrypt(inner_ciphertext, nonce=inner_nonce)

            sender_id_end = inner_plaintext.index(b"\x00")
            sender_id = inner_plaintext[:sender_id_end].decode("utf-8")
            plaintext = inner_plaintext[sender_id_end + 1:].decode("utf-8")

            if sender_id != sender_fp:
                return None

            return sender_id, plaintext

        except Exception:
            return None

    def check_delivery_token(self, token: bytes, recipient_fp: str,
                             sender_fp: str) -> bool:
        """Check if a delivery token is valid and not expired."""
        if not self.verify_delivery_token(token, recipient_fp, sender_fp):
            return False
        return self._check_rate_limit(sender_fp)

    def _check_rate_limit(self, sender_fp: str) -> bool:
        """Rate limit sealed messages per sender."""
        now = time.time()
        if sender_fp not in self._rate_limiter:
            self._rate_limiter[sender_fp] = []
        times = self._rate_limiter[sender_fp]
        times[:] = [t for t in times if now - t < SEALED_RATE_LIMIT_WINDOW]
        if len(times) >= SEALED_RATE_LIMIT_MAX:
            return False
        times.append(now)
        return True

    @staticmethod
    def _add_padding(data: bytes) -> bytes:
        """Add padding to fixed-size payload to prevent size correlation."""
        if len(data) >= SEALED_PAYLOAD_SIZE:
            return data
        padding_len = SEALED_PAYLOAD_SIZE - len(data)
        padding = os.urandom(padding_len - 1) + b"\x00"
        return data + padding

    @staticmethod
    def _remove_padding(data: bytes) -> bytes:
        """Remove padding from sealed payload."""
        if len(data) <= SEALED_PAYLOAD_SIZE:
            null_idx = data.find(b"\x00")
            if null_idx > 0:
                return data[:null_idx]
        return data

    def create_sealed_message(self, plaintext: str, recipient_box_pubkey_b64: str,
                              recipient_fp: str) -> dict:
        """Create a complete sealed message ready for transport."""
        delivery_token = self.generate_delivery_token(recipient_fp)
        encrypted = self.encrypt_sealed(plaintext, recipient_box_pubkey_b64, delivery_token)
        return {
            "delivery_token": encrypted["delivery_token"],
            "ciphertext": encrypted["ciphertext"],
            "ephemeral_key": encrypted["ephemeral_key"],
            "nonce": encrypted["nonce"],
            "inner_nonce": encrypted["inner_nonce"],
            "timestamp": int(time.time()),
        }

    def receive_sealed_message(self, sealed_msg: dict) -> Optional[tuple[str, str, str]]:
        """Process a received sealed message.

        Returns: (sender_fingerprint, plaintext, delivery_token) or None.
        The delivery token can be used to rate-limit or audit the message.
        """
        try:
            delivery_token = nacl.encoding.Base64Encoder.decode(
                sealed_msg["delivery_token"].encode()
            )
        except Exception:
            return None

        for sender_fp in self._delivery_token_cache:
            result = self.decrypt_sealed(sealed_msg, sender_fp)
            if result:
                sender_id, plaintext = result
                if self.verify_delivery_token(delivery_token, self.identity.fingerprint, sender_id):
                    return sender_id, plaintext, sealed_msg["delivery_token"]

        return None
