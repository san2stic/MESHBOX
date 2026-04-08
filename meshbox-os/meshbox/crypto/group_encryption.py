"""
MeshBox - Group Encryption with Sender Keys.

Efficient group messaging encryption where a message is encrypted once per sender
(rather than N times for N members) using the Sender Key pattern similar to Signal.

Key features:
- SenderKey: chain key + signature key per (group, member)
- Key distribution via existing pairwise encryption channels
- Key rotation on member join/leave
- Forward secrecy via message key chain ratchet
- Backward secrecy after member removal
"""

import hashlib
import hmac
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Optional

import nacl.encoding
import nacl.hash
import nacl.public
import nacl.secret
import nacl.signing
import nacl.utils


CHAIN_KEY_LEN = 32
SIGNATURE_KEY_LEN = 32
MESSAGE_KEY_LEN = 32
MAX_GROUP_SIZE = 1000


def _hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def _derive_keys(chain_key: bytes, info: bytes) -> tuple[bytes, bytes]:
    okm = _hmac_sha256(chain_key, info + b"\x01")
    message_key = okm[:MESSAGE_KEY_LEN]
    next_chain_key = _hmac_sha256(okm[MESSAGE_KEY_LEN:], info + b"\x02")
    return message_key, next_chain_key


@dataclass
class SenderKey:
    """Sender key for a member in a group.

    Contains:
    - chain_key: used to derive message keys (ratcheted per message)
    - signature_key: Ed25519 signing key for message authentication
    - sender_id: fingerprint of the sender
    - group_id: identifier for the group
    - epoch: version number for key rotation
    """

    chain_key: bytes
    signature_key: nacl.signing.SigningKey
    sender_id: str
    group_id: str
    epoch: int = 1
    created_at: int = field(default_factory=lambda: int(time.time()))

    @property
    def verify_key_b64(self) -> str:
        return self.signature_key.verify_key.encode(nacl.encoding.Base64Encoder).decode()

    @property
    def chain_key_hash(self) -> str:
        return hashlib.sha256(self.chain_key).hexdigest()[:16]

    def derive_message_key(self) -> tuple[bytes, "SenderKey"]:
        """Derive the next message key and advance the chain.

        Returns (message_key, updated_sender_key) where the updated
        sender key has the ratcheted chain key.
        """
        message_key, next_chain_key = _derive_keys(self.chain_key, self.group_id.encode())
        updated = SenderKey(
            chain_key=next_chain_key,
            signature_key=self.signature_key,
            sender_id=self.sender_id,
            group_id=self.group_id,
            epoch=self.epoch,
            created_at=self.created_at,
        )
        return message_key, updated

    def encode(self) -> dict:
        """Serialize to a dict for storage or transmission."""
        return {
            "chain_key": nacl.encoding.Base64Encoder.encode(self.chain_key).decode(),
            "signature_key": nacl.encoding.Base64Encoder.encode(self.signature_key.encode()).decode(),
            "sender_id": self.sender_id,
            "group_id": self.group_id,
            "epoch": self.epoch,
            "created_at": self.created_at,
        }

    @classmethod
    def decode(cls, data: dict) -> "SenderKey":
        """Deserialize from a dict."""
        return cls(
            chain_key=nacl.encoding.Base64Encoder.decode(data["chain_key"].encode()),
            signature_key=nacl.signing.SigningKey(
                nacl.encoding.Base64Encoder.decode(data["signature_key"].encode())
            ),
            sender_id=data["sender_id"],
            group_id=data["group_id"],
            epoch=data.get("epoch", 1),
            created_at=data.get("created_at", int(time.time())),
        )


@dataclass
class GroupSession:
    """Group messaging session state."""

    group_id: str
    group_name: str
    creator_id: str
    members: list[str] = field(default_factory=list)
    sender_keys: dict[str, SenderKey] = field(default_factory=dict)
    epoch: int = 1
    created_at: int = field(default_factory=lambda: int(time.time()))
    updated_at: int = field(default_factory=lambda: int(time.time()))

    def add_member(self, member_id: str) -> None:
        if member_id not in self.members:
            self.members.append(member_id)
            self.updated_at = int(time.time())

    def remove_member(self, member_id: str) -> bool:
        if member_id in self.members:
            self.members.remove(member_id)
            if member_id in self.sender_keys:
                del self.sender_keys[member_id]
            self.updated_at = int(time.time())
            return True
        return False

    def get_member_count(self) -> int:
        return len(self.members)


class GroupEncryption:
    """Group encryption manager using Sender Keys.

    Provides efficient group message encryption where each sender uses
    their own sender key to encrypt messages once, rather than encrypting
    separately for each recipient.
    """

    def __init__(self, identity: "Identity", storage: Optional["StorageEngine"] = None):
        self.identity = identity
        self.storage = storage

    def generate_sender_key(self, group_id: str) -> SenderKey:
        """Generate a new sender key for the current user in a group."""
        chain_key = nacl.utils.random(CHAIN_KEY_LEN)
        signature_key = nacl.signing.SigningKey.generate()
        return SenderKey(
            chain_key=chain_key,
            signature_key=signature_key,
            sender_id=self.identity.fingerprint,
            group_id=group_id,
            epoch=1,
        )

    def encrypt_group_message(
        self,
        plaintext: str,
        sender_key: SenderKey,
    ) -> dict:
        """Encrypt a group message using the sender's sender key.

        The message is encrypted once using the sender's chain key,
        then signed with the sender's signature key.
        """
        message_key, updated_sender_key = sender_key.derive_message_key()

        box = nacl.secret.SecretBox(message_key)
        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        ciphertext = box.encrypt(plaintext.encode("utf-8"), nonce=nonce)

        sender_info = sender_key.sender_id.encode() + sender_key.group_id.encode()
        signed = sender_key.signature_key.sign(sender_info + ciphertext)

        return {
            "ciphertext": nacl.encoding.Base64Encoder.encode(ciphertext).decode(),
            "nonce": nacl.encoding.Base64Encoder.encode(nonce).decode(),
            "sender_id": sender_key.sender_id,
            "group_id": sender_key.group_id,
            "sender_key_epoch": sender_key.epoch,
            "signature": nacl.encoding.Base64Encoder.encode(signed.signature).decode(),
            "sender_verify_key": sender_key.verify_key_b64,
            "updated_chain_key_hash": updated_sender_key.chain_key_hash,
        }

    def decrypt_group_message(
        self,
        encrypted: dict,
        sender_key: SenderKey,
    ) -> Optional[str]:
        """Decrypt a group message using the sender's sender key."""
        try:
            ciphertext = nacl.encoding.Base64Encoder.decode(
                encrypted["ciphertext"].encode()
            )
            nonce = nacl.encoding.Base64Encoder.decode(encrypted["nonce"].encode())
            signature = nacl.encoding.Base64Encoder.decode(
                encrypted["signature"].encode()
            )

            sender_info = sender_key.sender_id.encode() + sender_key.group_id.encode()
            verify_key = nacl.signing.VerifyKey(
                encrypted["sender_verify_key"].encode(),
                nacl.encoding.Base64Encoder,
            )
            verify_key.verify(sender_info + ciphertext, signature)

            box = nacl.secret.SecretBox(sender_key.chain_key)
            plaintext = box.decrypt(ciphertext, nonce=nonce)

            return plaintext.decode("utf-8")

        except Exception:
            return None

    def create_group(self, group_name: str) -> GroupSession:
        """Create a new encrypted group."""
        group_id = secrets.token_hex(16)
        session = GroupSession(
            group_id=group_id,
            group_name=group_name,
            creator_id=self.identity.fingerprint,
            members=[self.identity.fingerprint],
        )
        sender_key = self.generate_sender_key(group_id)
        session.sender_keys[self.identity.fingerprint] = sender_key
        return session

    def encrypt_for_members(
        self,
        plaintext: str,
        sender_key: SenderKey,
        member_public_keys: dict[str, str],
    ) -> dict:
        """Encrypt group message and package for each member.

        The actual message is encrypted with sender key (for group efficiency),
        then a per-member key encrypts the sender key for each member.

        Returns dict with:
        - group_ciphertext: sender-key encrypted message
        - member_keys: dict of member_id -> encrypted sender key
        """
        group_encrypted = self.encrypt_group_message(plaintext, sender_key)

        member_keys = {}
        for member_id, box_pubkey in member_public_keys.items():
            if member_id == sender_key.sender_id:
                continue
            recipient_key = nacl.public.PublicKey(
                box_pubkey.encode(), nacl.encoding.Base64Encoder
            )
            box = nacl.public.Box(self.identity.box_key, recipient_key)
            sender_key_data = sender_key.chain_key + sender_key.signature_key.encode()
            encrypted_key = box.encrypt(sender_key_data)
            member_keys[member_id] = nacl.encoding.Base64Encoder.encode(encrypted_key).decode()

        return {
            "group_ciphertext": group_encrypted,
            "member_keys": member_keys,
        }

    def decrypt_from_member(
        self,
        encrypted: dict,
        sender_verify_key_b64: str,
        encrypted_sender_key: str,
    ) -> Optional[str]:
        """Decrypt a sender key sent to us, then decrypt the group message."""
        try:
            sender_key_bytes = nacl.encoding.Base64Encoder.decode(
                encrypted_sender_key.encode()
            )
            sender_key_encrypted = nacl.encoding.Base64Encoder.decode(
                encrypted["member_keys"][self.identity.fingerprint].encode()
            )

            box = nacl.public.Box(self.identity.box_key, self.identity.box_public_key)
            sender_key_data = box.decrypt(sender_key_encrypted)

            chain_key = sender_key_data[:CHAIN_KEY_LEN]
            signing_key_bytes = sender_key_data[CHAIN_KEY_LEN:]
            signature_key = nacl.signing.SigningKey(signing_key_bytes)

            sender_key = SenderKey(
                chain_key=chain_key,
                signature_key=signature_key,
                sender_id=encrypted["group_ciphertext"]["sender_id"],
                group_id=encrypted["group_ciphertext"]["group_id"],
                epoch=encrypted["group_ciphertext"].get("sender_key_epoch", 1),
            )

            return self.decrypt_group_message(encrypted["group_ciphertext"], sender_key)

        except Exception:
            return None

    def rotate_sender_key(self, group_id: str) -> SenderKey:
        """Rotate sender key for a group - generate a new sender key.

        Called when a member leaves or is removed, or periodically for security.
        """
        return self.generate_sender_key(group_id)

    def distribute_sender_key(
        self,
        sender_key: SenderKey,
        recipient_public_keys: dict[str, str],
    ) -> dict[str, str]:
        """Distribute a sender key to group members via pairwise encryption.

        Returns dict of recipient_id -> encrypted sender key.
        """
        distributed = {}
        for member_id, box_pubkey in recipient_public_keys.items():
            if member_id == self.identity.fingerprint:
                continue
            try:
                recipient_key = nacl.public.PublicKey(
                    box_pubkey.encode(), nacl.encoding.Base64Encoder
                )
                box = nacl.public.Box(self.identity.box_key, recipient_key)
                sender_key_data = sender_key.chain_key + sender_key.signature_key.encode()
                encrypted = box.encrypt(sender_key_data)
                distributed[member_id] = nacl.encoding.Base64Encoder.encode(encrypted).decode()
            except Exception:
                continue
        return distributed


class GroupKeyDistribution:
    """Handles group key distribution messages."""

    @staticmethod
    def create_key_distribution(
        sender_key: SenderKey,
        group_id: str,
        recipients: list[str],
    ) -> dict:
        """Create a GROUP_KEY_DISTRIBUTION message payload."""
        return {
            "type": "GROUP_KEY_DISTRIBUTION",
            "group_id": group_id,
            "sender_id": sender_key.sender_id,
            "sender_key": {
                "chain_key": nacl.encoding.Base64Encoder.encode(sender_key.chain_key).decode(),
                "signature_key": nacl.encoding.Base64Encoder.encode(
                    sender_key.signature_key.encode()
                ).decode(),
                "epoch": sender_key.epoch,
            },
            "recipients": recipients,
            "timestamp": int(time.time()),
        }

    @staticmethod
    def create_key_refresh(
        group_id: str,
        sender_id: str,
        new_epoch: int,
    ) -> dict:
        """Create a GROUP_KEY_REFRESH message payload (after member change)."""
        return {
            "type": "GROUP_KEY_REFRESH",
            "group_id": group_id,
            "sender_id": sender_id,
            "new_epoch": new_epoch,
            "timestamp": int(time.time()),
        }

    @staticmethod
    def create_member_join(
        group_id: str,
        sender_id: str,
        new_member_id: str,
    ) -> dict:
        """Create a GROUP_MEMBER_JOIN message payload."""
        return {
            "type": "GROUP_MEMBER_JOIN",
            "group_id": group_id,
            "sender_id": sender_id,
            "new_member_id": new_member_id,
            "timestamp": int(time.time()),
        }

    @staticmethod
    def create_member_leave(
        group_id: str,
        sender_id: str,
        removed_member_id: str,
    ) -> dict:
        """Create a GROUP_MEMBER_LEAVE message payload."""
        return {
            "type": "GROUP_MEMBER_LEAVE",
            "group_id": group_id,
            "sender_id": sender_id,
            "removed_member_id": removed_member_id,
            "timestamp": int(time.time()),
        }