"""
MeshBox - E2E encryption engine.
Uses libsodium (NaCl) via PyNaCl for asymmetric and symmetric encryption.
- Identity keys: Curve25519 (X25519) for key exchange
- Signatures: Ed25519 for message and profile authenticity
- Message encryption: XSalsa20-Poly1305 (crypto_box)
"""

import hashlib
import os
import time
from pathlib import Path
from typing import Optional

import nacl.encoding
import nacl.hash
import nacl.public
import nacl.signing
import nacl.utils


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


class CryptoEngine:
    """Encryption engine for MeshBox messages."""

    def __init__(self, identity: Identity):
        self.identity = identity

    def encrypt_message(self, plaintext: str, recipient_public_key_b64: str) -> dict:
        """
        Encrypt a message for a specific recipient.
        Uses crypto_box (Curve25519 + XSalsa20-Poly1305).
        """
        recipient_key = nacl.public.PublicKey(
            recipient_public_key_b64.encode(), nacl.encoding.Base64Encoder
        )

        box = nacl.public.Box(self.identity.box_key, recipient_key)
        encrypted = box.encrypt(plaintext.encode("utf-8"))
        signed = self.identity.signing_key.sign(encrypted)

        return {
            "ciphertext": nacl.encoding.Base64Encoder.encode(signed.message).decode(),
            "signature": nacl.encoding.Base64Encoder.encode(signed.signature).decode(),
            "sender_fingerprint": self.identity.fingerprint,
            "sender_verify_key": self.identity.verify_key.encode(
                nacl.encoding.Base64Encoder
            ).decode(),
            "sender_box_key": self.identity.box_public_key.encode(
                nacl.encoding.Base64Encoder
            ).decode(),
            "timestamp": int(time.time()),
            "version": 1,
        }

    def decrypt_message(self, encrypted_msg: dict) -> Optional[str]:
        """
        Decrypt a received message.
        Verifies the signature then decrypts the content.
        """
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
    def verify_proof_of_work(data: bytes, nonce: int, difficulty: int = 16) -> bool:
        """Verify a proof-of-work."""
        target = 2 ** (256 - difficulty)
        attempt = data + nonce.to_bytes(8, "big")
        h = int(hashlib.sha256(attempt).hexdigest(), 16)
        return h < target
