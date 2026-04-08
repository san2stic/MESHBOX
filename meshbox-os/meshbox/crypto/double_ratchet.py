"""
Double Ratchet Protocol (Signal Protocol) for E2E encryption.

This module implements:
- X3DH (Extended Triple Diffie-Hellman) session initialization
- Double Ratchet with symmetric-key ratchet + DH ratchet
- Header encryption for metadata protection
- Message key derivation for forward secrecy and post-compromise security
"""

import hashlib
import hmac
import os
import struct
import time
from dataclasses import dataclass, field
from typing import Optional

import nacl.encoding
import nacl.hash
import nacl.public
import nacl.secret
import nacl.signing
import nacl.utils

from meshbox.crypto import Identity


@dataclass
class PreKeyBundle:
    """Pre-key bundle for X3DH key agreement."""
    identity_key: bytes  # Identity public key (Curve25519)
    signed_prekey: bytes  # Signed pre-key public
    signed_prekey_id: int
    signed_prekey_sig: bytes
    one_time_prekey: Optional[bytes] = None  # Optional one-time pre-key


@dataclass
class X3DHResult:
    """Result of X3DH key agreement."""
    shared_secret: bytes  # 32-byte root key
    ephemeral_public: bytes
    used_one_time_key: bool


class X3DH:
    """Extended Triple Diffie-Hellman key agreement."""

    @staticmethod
    def generate_prekeys(count: int = 100) -> list[tuple[int, bytes]]:
        """Generate pre-key pairs for X3DH. Returns list of (id, public_key)."""
        prekeys = []
        for i in range(count):
            private_key = nacl.public.PrivateKey.generate()
            prekeys.append((i, private_key.public_key.encode(nacl.encoding.RawEncoder)))
        return prekeys

    @staticmethod
    def create_prekey_bundle(identity: Identity, prekey_id: int, prekey_private: nacl.public.PrivateKey) -> PreKeyBundle:
        """Create a pre-key bundle for sharing."""
        signed_prekey = prekey_private.public_key.encode(nacl.encoding.RawEncoder)
        signed_prekey_sig = identity.signing_key.sign(signed_prekey).signature
        return PreKeyBundle(
            identity_key=identity.box_public_key.encode(nacl.encoding.RawEncoder),
            signed_prekey=signed_prekey,
            signed_prekey_id=prekey_id,
            signed_prekey_sig=signed_prekey_sig,
        )

    @staticmethod
    def initiate(identity: Identity, bundle: PreKeyBundle) -> X3DHResult:
        """Initiate X3DH as the sender.

        Performs:
        - DH1: identity_key (sender) <-> signed_prekey (recipient)
        - DH2: ephemeral_key (sender) <-> identity_key (recipient)
        - DH3: ephemeral_key (sender) <-> signed_prekey (recipient)
        - Optional DH4 with one-time pre-key
        """
        sender_ephemeral = nacl.public.PrivateKey.generate()

        recipient_identity_key = nacl.public.PublicKey(
            bundle.identity_key, nacl.encoding.RawEncoder
        )
        recipient_signed_prekey = nacl.public.PublicKey(
            bundle.signed_prekey, nacl.encoding.RawEncoder
        )

        dh1 = nacl.bindings.crypto_scalarmult(
            identity.box_key.encode(nacl.encoding.RawEncoder),
            recipient_signed_prekey.encode(nacl.encoding.RawEncoder),
        )

        dh2 = nacl.bindings.crypto_scalarmult(
            sender_ephemeral.encode(nacl.encoding.RawEncoder),
            recipient_identity_key.encode(nacl.encoding.RawEncoder),
        )

        dh3 = nacl.bindings.crypto_scalarmult(
            sender_ephemeral.encode(nacl.encoding.RawEncoder),
            recipient_signed_prekey.encode(nacl.encoding.RawEncoder),
        )

        shared = dh1 + dh2 + dh3
        shared_secret = hashlib.sha256(shared).digest()

        used_one_time = False
        if bundle.one_time_prekey:
            recipient_otpk = nacl.public.PublicKey(
                bundle.one_time_prekey, nacl.encoding.RawEncoder
            )
            dh4 = nacl.bindings.crypto_scalarmult(
                sender_ephemeral.encode(nacl.encoding.RawEncoder),
                recipient_otpk.encode(nacl.encoding.RawEncoder),
            )
            shared_secret = hashlib.sha256(shared_secret + dh4).digest()
            used_one_time = True

        return X3DHResult(
            shared_secret=shared_secret,
            ephemeral_public=sender_ephemeral.public_key.encode(nacl.encoding.RawEncoder),
            used_one_time_key=used_one_time,
        )

    @staticmethod
    def respond(identity: Identity, sender_ephemeral: bytes, sender_identity: bytes,
                sender_signed_prekey: bytes, used_otpk: bool = False,
                otpk_private: Optional[nacl.public.PrivateKey] = None) -> bytes:
        """Respond to X3DH as the recipient.

        Performs the same DH operations in reverse to derive the same shared secret.
        """
        sender_ephemeral_key = nacl.public.PublicKey(sender_ephemeral, nacl.encoding.RawEncoder)
        sender_identity_key = nacl.public.PublicKey(sender_identity, nacl.encoding.RawEncoder)
        sender_signed_key = nacl.public.PublicKey(sender_signed_prekey, nacl.encoding.RawEncoder)

        dh1 = nacl.bindings.crypto_scalarmult(
            identity.box_key.encode(nacl.encoding.RawEncoder),
            sender_signed_key.encode(nacl.encoding.RawEncoder),
        )

        dh2 = nacl.bindings.crypto_scalarmult(
            identity.box_key.encode(nacl.encoding.RawEncoder),
            sender_identity_key.encode(nacl.encoding.RawEncoder),
        )

        if otpk_private:
            dh3 = nacl.bindings.crypto_scalarmult(
                otpk_private.encode(nacl.encoding.RawEncoder),
                sender_ephemeral_key.encode(nacl.encoding.RawEncoder),
            )
            shared = dh1 + dh2 + dh3
        else:
            dh3 = nacl.bindings.crypto_scalarmult(
                identity.box_key.encode(nacl.encoding.RawEncoder),
                sender_ephemeral_key.encode(nacl.encoding.RawEncoder),
            )
            shared = dh1 + dh2 + dh3

        return hashlib.sha256(shared).digest()


def kdf_rk(root_key: bytes, dh_output: bytes) -> tuple[bytes, bytes]:
    """Root Key Derivation Function - derives new root key and receiving chain key."""
    output = hmac.new(root_key, dh_output, hashlib.sha256).digest()
    return output[:32], output[32:]


def kdf_ck(chain_key: bytes) -> tuple[bytes, bytes]:
    """Chain Key Derivation - advances chain and derives message key."""
    derived = hmac.new(chain_key, b"\x01", hashlib.sha256).digest()
    message_key = hmac.new(chain_key, b"\x02", hashlib.sha256).digest()
    return derived[:32], message_key[:32]


class RatchetState:
    """Persistent ratchet state for a session."""

    def __init__(self):
        self.root_key: bytes = b""
        self.sending_chain_key: bytes = b""
        self.receiving_chain_key: bytes = b""
        self.sending_ratchet_key: Optional[bytes] = None
        self.receiving_ratchet_key: Optional[bytes] = None
        self.previous_chain_length: int = 0
        self.sending_ratchet_key_public: Optional[bytes] = None
        self.receiving_ratchet_key_public: Optional[bytes] = None
        self.message_number: int = 0
        self.previous_message_number: int = 0
        self.peer_fingerprint: str = ""
        self.created_at: int = 0
        self.updated_at: int = 0

    def to_dict(self) -> dict:
        return {
            "root_key": self.root_key.hex(),
            "sending_chain_key": self.sending_chain_key.hex(),
            "receiving_chain_key": self.receiving_chain_key.hex(),
            "sending_ratchet_key": self.sending_ratchet_key.hex() if self.sending_ratchet_key else "",
            "receiving_ratchet_key": self.receiving_ratchet_key.hex() if self.receiving_ratchet_key else "",
            "previous_chain_length": self.previous_chain_length,
            "sending_ratchet_key_public": self.sending_ratchet_key_public.hex() if self.sending_ratchet_key_public else "",
            "receiving_ratchet_key_public": self.receiving_ratchet_key_public.hex() if self.receiving_ratchet_key_public else "",
            "message_number": self.message_number,
            "previous_message_number": self.previous_message_number,
            "peer_fingerprint": self.peer_fingerprint,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "RatchetState":
        state = cls()
        state.root_key = bytes.fromhex(data.get("root_key", ""))
        state.sending_chain_key = bytes.fromhex(data.get("sending_chain_key", ""))
        state.receiving_chain_key = bytes.fromhex(data.get("receiving_chain_key", ""))
        state.sending_ratchet_key = bytes.fromhex(data["sending_ratchet_key"]) if data.get("sending_ratchet_key") else None
        state.receiving_ratchet_key = bytes.fromhex(data["receiving_ratchet_key"]) if data.get("receiving_ratchet_key") else None
        state.previous_chain_length = data.get("previous_chain_length", 0)
        state.sending_ratchet_key_public = bytes.fromhex(data["sending_ratchet_key_public"]) if data.get("sending_ratchet_key_public") else None
        state.receiving_ratchet_key_public = bytes.fromhex(data["receiving_ratchet_key_public"]) if data.get("receiving_ratchet_key_public") else None
        state.message_number = data.get("message_number", 0)
        state.previous_message_number = data.get("previous_message_number", 0)
        state.peer_fingerprint = data.get("peer_fingerprint", "")
        state.created_at = data.get("created_at", 0)
        state.updated_at = data.get("updated_at", 0)
        return state


class HeaderEncryptor:
    """Header encryption for Double Ratchet messages."""

    @staticmethod
    def create_header_key(secret: bytes) -> bytes:
        """Derive header encryption key from shared secret."""
        return hashlib.sha256(b"header-key" + secret).digest()

    @staticmethod
    def encrypt_header(header: dict, key: bytes) -> bytes:
        """Encrypt header with AES-GCM-like approach using SecretBox."""
        header_bytes = msgpack.packb(header, use_bin_type=True)
        box = nacl.secret.SecretBox(key)
        return box.encrypt(header_bytes)

    @staticmethod
    def decrypt_header(ciphertext: bytes, key: bytes) -> Optional[dict]:
        """Decrypt header."""
        try:
            box = nacl.secret.SecretBox(key)
            header_bytes = box.decrypt(ciphertext)
            import msgpack
            return msgpack.unpackb(header_bytes, raw=True)
        except Exception:
            return None


import msgpack


class DoubleRatchet:
    """Double Ratchet algorithm implementation."""

    MAX_SKIP = 1000  # Maximum messages to skip

    def __init__(self, identity: Identity, peer_fingerprint: str, storage=None):
        self.identity = identity
        self.peer_fingerprint = peer_fingerprint
        self.storage = storage
        self.state = RatchetState()
        self.skipped_messages: dict[int, bytes] = {}
        self.header_key: Optional[bytes] = None
        self.peer_header_key: Optional[bytes] = None
        self._initialized = False

    def initialize_outgoing(self, x3dh_result: X3DHResult, peer_ratchet_key: bytes) -> bytes:
        """Initialize ratchet as the sender after X3DH."""
        self.state.root_key = x3dh_result.shared_secret
        self.state.sending_ratchet_key = nacl.public.PrivateKey.generate()
        self.state.sending_ratchet_key_public = self.state.sending_ratchet_key.public_key.encode(nacl.encoding.RawEncoder)
        self.state.receiving_ratchet_key = peer_ratchet_key

        dh_output = nacl.bindings.crypto_scalarmult(
            self.state.sending_ratchet_key.encode(nacl.encoding.RawEncoder),
            peer_ratchet_key,
        )
        self.state.root_key, self.state.sending_chain_key = kdf_rk(self.state.root_key, dh_output)

        self.header_key = HeaderEncryptor.create_header_key(self.state.root_key)
        self._initialized = True
        self.state.peer_fingerprint = self.peer_fingerprint
        self.state.created_at = int(time.time())
        self.state.updated_at = int(time.time())

        if self.storage:
            self.storage.save_ratchet_state(self.peer_fingerprint, self.state.to_dict())

        return self.state.sending_ratchet_key_public

    def initialize_incoming(self, shared_secret: bytes, our_ratchet_key: bytes,
                            peer_ratchet_public: bytes) -> None:
        """Initialize ratchet as the recipient after X3DH."""
        self.state.root_key = shared_secret
        self.state.receiving_ratchet_key = our_ratchet_key
        self.state.sending_ratchet_key_public = peer_ratchet_public

        dh_output = nacl.bindings.crypto_scalarmult(
            our_ratchet_key,
            peer_ratchet_public,
        )
        self.state.root_key, self.state.receiving_chain_key = kdf_rk(self.state.root_key, dh_output)

        self.peer_header_key = HeaderEncryptor.create_header_key(self.state.root_key)
        self._initialized = True
        self.state.peer_fingerprint = self.peer_fingerprint
        self.state.created_at = int(time.time())
        self.state.updated_at = int(time.time())

        if self.storage:
            self.storage.save_ratchet_state(self.peer_fingerprint, self.state.to_dict())

    def load_state(self, state_dict: dict) -> None:
        """Load ratchet state from stored dict."""
        self.state = RatchetState.from_dict(state_dict)
        self.header_key = HeaderEncryptor.create_header_key(self.state.root_key)
        self._initialized = True

    def encrypt(self, plaintext: bytes) -> dict:
        """Encrypt a message using the Double Ratchet."""
        if not self._initialized:
            raise RuntimeError("Ratchet not initialized")

        message_key = self._derive_message_key()

        body_key = hashlib.sha256(b"body-key" + message_key).digest()
        box = nacl.secret.SecretBox(body_key)
        ciphertext = box.encrypt(plaintext)

        header = {
            "ratchet": self.state.sending_ratchet_key_public,
            "n": self.state.message_number,
            "pn": self.state.previous_chain_length,
        }
        encrypted_header = HeaderEncryptor.encrypt_header(header, self.header_key)

        self.state.message_number += 1
        self.state.updated_at = int(time.time())

        if self.storage:
            self.storage.save_ratchet_state(self.peer_fingerprint, self.state.to_dict())

        return {
            "ciphertext": ciphertext.hex(),
            "header": encrypted_header.hex(),
            "message_number": self.state.message_number - 1,
        }

    def decrypt(self, encrypted: dict) -> Optional[bytes]:
        """Decrypt a message using the Double Ratchet."""
        if not self._initialized:
            return None

        try:
            encrypted_header = bytes.fromhex(encrypted["header"])
            ciphertext = bytes.fromhex(encrypted["ciphertext"])

            if not self.peer_header_key:
                return None

            header = HeaderEncryptor.decrypt_header(encrypted_header, self.peer_header_key)
            if not header:
                return None

            peer_ratchet_key = bytes(header[b"r"])
            message_num = int(header[b"n"])
            prev_chain_len = int(header[b"pn"])

            if self.state.receiving_ratchet_key != peer_ratchet_key:
                self._skip_messages(prev_chain_len)
                self._perform_dh_ratchet(peer_ratchet_key)

            if message_num < self.state.message_number:
                skipped_key = self._get_skipped_message_key(message_num)
                if skipped_key:
                    return self._decrypt_with_key(ciphertext, skipped_key)
                return None

            while self.state.message_number < message_num:
                self._derive_message_key()
                self.state.message_number += 1

            message_key = self._derive_message_key()
            plaintext = self._decrypt_with_key(ciphertext, message_key)

            self.state.updated_at = int(time.time())
            if self.storage:
                self.storage.save_ratchet_state(self.peer_fingerprint, self.state.to_dict())

            return plaintext

        except Exception:
            return None

    def _derive_message_key(self) -> bytes:
        """Derive the next message key from the sending chain."""
        self.state.sending_chain_key, message_key = kdf_ck(self.state.sending_chain_key)
        return message_key

    def _decrypt_with_key(self, ciphertext: bytes, key: bytes) -> Optional[bytes]:
        """Decrypt ciphertext with a specific message key."""
        try:
            box = nacl.secret.SecretBox(key)
            return box.decrypt(ciphertext)
        except Exception:
            return None

    def _skip_messages(self, until: int) -> None:
        """Skip ahead in the receiving chain to handle out-of-order messages."""
        while self.state.message_number < until:
            self.state.receiving_chain_key, skipped_key = kdf_ck(self.state.receiving_chain_key)
            self.skipped_messages[self.state.message_number] = skipped_key
            self.state.message_number += 1

    def _get_skipped_message_key(self, message_num: int) -> Optional[bytes]:
        """Get a previously skipped message key."""
        return self.skipped_messages.pop(message_num, None)

    def _perform_dh_ratchet(self, peer_ratchet_key: bytes) -> None:
        """Perform the DH ratchet step."""
        self.state.previous_chain_length = self.state.message_number
        self.state.message_number = 0
        self.state.previous_message_number = self.state.message_number

        self.state.receiving_ratchet_key = peer_ratchet_key

        dh_output = nacl.bindings.crypto_scalarmult(
            self.state.sending_ratchet_key.encode(nacl.encoding.RawEncoder),
            peer_ratchet_key,
        )
        self.state.root_key, self.state.receiving_chain_key = kdf_rk(self.state.root_key, dh_output)

        self.state.sending_ratchet_key = nacl.public.PrivateKey.generate()
        self.state.sending_ratchet_key_public = self.state.sending_ratchet_key.public_key.encode(nacl.encoding.RawEncoder)

        dh_output = nacl.bindings.crypto_scalarmult(
            self.state.sending_ratchet_key.encode(nacl.encoding.RawEncoder),
            peer_ratchet_key,
        )
        self.state.root_key, self.state.sending_chain_key = kdf_rk(self.state.root_key, dh_output)

        self.header_key = HeaderEncryptor.create_header_key(self.state.root_key)
        self.peer_header_key = HeaderEncryptor.create_header_key(self.state.root_key)


class DoubleRatchetSession:
    """High-level session manager for Double Ratchet."""

    def __init__(self, identity: Identity, peer_fingerprint: str, storage=None):
        self.identity = identity
        self.peer_fingerprint = peer_fingerprint
        self.storage = storage
        self.ratchet = DoubleRatchet(identity, peer_fingerprint, storage)
        self._dh_ratchet_interval = 100  # Perform DH ratchet every N messages
        self._message_count = 0

    @classmethod
    def load(cls, identity: Identity, peer_fingerprint: str, storage) -> Optional["DoubleRatchetSession"]:
        """Load an existing session from storage."""
        session = cls(identity, peer_fingerprint, storage)
        state_dict = storage.get_ratchet_state(peer_fingerprint) if storage else None
        if state_dict:
            session.ratchet.load_state(state_dict)
            return session
        return None

    def encrypt(self, plaintext: str) -> dict:
        """Encrypt a message string."""
        self._message_count += 1

        if self._message_count % self._dh_ratchet_interval == 0:
            self._perform_scheduled_dh_ratchet()

        return self.ratchet.encrypt(plaintext.encode("utf-8"))

    def decrypt(self, encrypted: dict) -> Optional[str]:
        """Decrypt a message, returning plaintext string."""
        plaintext = self.ratchet.decrypt(encrypted)
        if plaintext:
            return plaintext.decode("utf-8")
        return None

    def _perform_scheduled_dh_ratchet(self) -> None:
        """Perform scheduled DH ratchet for post-compromise security."""
        if self.ratchet.state.sending_ratchet_key:
            peer_key = self.ratchet.state.receiving_ratchet_key
            if peer_key:
                self.ratchet._perform_dh_ratchet(peer_key)

    def get_state(self) -> dict:
        """Get current session state for storage."""
        return self.ratchet.state.to_dict()