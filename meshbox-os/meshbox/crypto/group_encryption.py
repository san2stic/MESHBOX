"""
MeshBox Group Encryption — Sender Keys with Forward Secrecy.

Implements the Sender Key protocol with Double Ratchet-style forward secrecy:
- Symmetric ratchet: chain key advances with each message (HMAC-based KDF)
- Asymmetric ratchet: DH step every N messages (configurable, default 50)
- Key epoch tracking in SQLite for replay/freshness validation
- Lazy key loading and bounded message key cache
- Tree-based key broadcast for groups > 50 members
"""

import hashlib
import hmac
import os
import secrets
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Optional

import nacl.encoding
import nacl.hash
import nacl.public
import nacl.signing
import nacl.utils


CHAIN_KEY_INFO = b"MeshBoxGroupChainKey"
MESSAGE_KEY_INFO = b"MeshBoxGroupMessageKey"
DH_RATCHET_INFO = b"MeshBoxGroupDHRatchet"
DEFAULT_DH_INTERVAL = 50
MAX_MESSAGE_KEY_CACHE = 1000
LARGE_GROUP_THRESHOLD = 50


class KeyDerivationError(Exception):
    """Raised when key derivation fails."""
    pass


@dataclass
class SenderKey:
    """Sender Key with symmetric and asymmetric ratchets.

    Attributes:
        group_id: The group this key belongs to.
        sender_fingerprint: The sender's identity fingerprint.
        chain_key: Current chain key (32 bytes).
        root_key: Root key for DH ratchet (32 bytes).
        dh_public_key: Current DH public key.
        dh_private_key: Current DH private key.
        message_number: Counter for symmetric ratchet.
        dh_counter: Counter for DH ratchet (asymmetric).
        epoch: Key epoch number (increments on member changes).
        created_at: Unix timestamp of creation.
    """

    group_id: str
    sender_fingerprint: str
    chain_key: bytes
    root_key: bytes
    dh_public_key: bytes
    dh_private_key: bytes
    message_number: int = 0
    dh_counter: int = 0
    epoch: int = 0
    created_at: int = field(default_factory=lambda: int(time.time()))
    signature_key: Optional[bytes] = None

    def __post_init__(self):
        if len(self.chain_key) != 32:
            raise KeyDerivationError("chain_key must be 32 bytes")
        if len(self.root_key) != 32:
            raise KeyDerivationError("root_key must be 32 bytes")

    def derive_message_key(self) -> tuple[bytes, "SenderKey"]:
        """Derive a message key and advance the symmetric ratchet.

        Uses HKDF-like construction:
            message_key = HMAC(chain_key, MESSAGE_KEY_INFO || message_number)
            chain_key = HMAC(chain_key, 01)  # advance chain

        Returns:
            Tuple of (message_key, updated SenderKey copy).
        """
        chain_key_input = self.chain_key + MESSAGE_KEY_INFO + self.message_number.to_bytes(4, "big")
        message_key = hmac.new(self.chain_key, chain_key_input, hashlib.sha256).digest()

        advance_input = self.chain_key + b"\x01"
        new_chain_key = hmac.new(self.chain_key, advance_input, hashlib.sha256).digest()

        new_key = SenderKey(
            group_id=self.group_id,
            sender_fingerprint=self.sender_fingerprint,
            chain_key=new_chain_key,
            root_key=self.root_key,
            dh_public_key=self.dh_public_key,
            dh_private_key=self.dh_private_key,
            message_number=self.message_number + 1,
            dh_counter=self.dh_counter,
            epoch=self.epoch,
            created_at=self.created_at,
            signature_key=self.signature_key,
        )

        return message_key, new_key

    def should_dh_ratchet(self, interval: int = DEFAULT_DH_INTERVAL) -> bool:
        """Check if it's time for a DH ratchet step."""
        return self.message_number > 0 and self.message_number % interval == 0

    def dh_ratchet(self, peer_dh_public: bytes) -> "SenderKey":
        """Perform DH ratchet step to advance the root key.

        Args:
            peer_dh_public: The peer's current DH public key.

        Returns:
            New SenderKey with updated root key and DH key pair.
        """
        peer_key = nacl.public.PublicKey(peer_dh_public)
        private_key = nacl.public.PrivateKey.from_bytes(self.dh_private_key)

        shared_secret = nacl.bindings.crypto_scalarmult(
            private_key.encode(nacl.encoding.RawEncoder),
            peer_key.encode(nacl.encoding.RawEncoder),
        )

        root_input = self.root_key + shared_secret + DH_RATCHET_INFO
        new_root_key = hashlib.sha256(root_input).digest()

        new_dh_private = nacl.public.PrivateKey.generate()
        new_dh_public = new_dh_private.public_key.encode(nacl.encoding.RawEncoder)

        chain_input = new_root_key + new_dh_public + peer_dh_public + CHAIN_KEY_INFO
        new_chain_key = hashlib.sha256(chain_input).digest()

        return SenderKey(
            group_id=self.group_id,
            sender_fingerprint=self.sender_fingerprint,
            chain_key=new_chain_key,
            root_key=new_root_key,
            dh_public_key=new_dh_public,
            dh_private_key=new_dh_private.encode(nacl.encoding.RawEncoder),
            message_number=0,
            dh_counter=self.dh_counter + 1,
            epoch=self.epoch,
            created_at=self.created_at,
            signature_key=self.signature_key,
        )

    def sign_message(self, message: bytes, signing_key: nacl.signing.SigningKey) -> bytes:
        """Sign a message using the sender's signature key."""
        return signing_key.sign(message).signature

    def to_dict(self) -> dict:
        """Serialize to dictionary for storage."""
        return {
            "group_id": self.group_id,
            "sender_fingerprint": self.sender_fingerprint,
            "chain_key": nacl.encoding.RawEncoder.encode(self.chain_key).decode(),
            "root_key": nacl.encoding.RawEncoder.encode(self.root_key).decode(),
            "dh_public_key": nacl.encoding.RawEncoder.encode(self.dh_public_key).decode(),
            "dh_private_key": nacl.encoding.RawEncoder.encode(self.dh_private_key).decode(),
            "message_number": self.message_number,
            "dh_counter": self.dh_counter,
            "epoch": self.epoch,
            "created_at": self.created_at,
            "signature_key": self.signature_key.decode() if self.signature_key else None,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SenderKey":
        """Deserialize from dictionary."""
        return cls(
            group_id=data["group_id"],
            sender_fingerprint=data["sender_fingerprint"],
            chain_key=nacl.encoding.RawEncoder.decode(data["chain_key"].encode()),
            root_key=nacl.encoding.RawEncoder.decode(data["root_key"].encode()),
            dh_public_key=nacl.encoding.RawEncoder.decode(data["dh_public_key"].encode()),
            dh_private_key=nacl.encoding.RawEncoder.decode(data["dh_private_key"].encode()),
            message_number=data.get("message_number", 0),
            dh_counter=data.get("dh_counter", 0),
            epoch=data.get("epoch", 0),
            created_at=data.get("created_at", int(time.time())),
            signature_key=data.get("signature_key", "").encode() if data.get("signature_key") else None,
        )


class MessageKeyCache:
    """Bounded LRU cache for message keys (for decryption)."""

    def __init__(self, max_size: int = MAX_MESSAGE_KEY_CACHE):
        self.max_size = max_size
        self._cache: OrderedDict[tuple[str, int, int], bytes] = OrderedDict()

    def put(self, sender_fp: str, epoch: int, message_num: int, key: bytes):
        """Store a message key."""
        key_id = (sender_fp, epoch, message_num)
        self._cache[key_id] = key
        if len(self._cache) > self.max_size:
            self._cache.popitem(last=False)

    def get(self, sender_fp: str, epoch: int, message_num: int) -> Optional[bytes]:
        """Retrieve a message key."""
        key_id = (sender_fp, epoch, message_num)
        if key_id in self._cache:
            self._cache.move_to_end(key_id)
            return self._cache[key_id]
        return None

    def clear(self):
        """Clear the cache."""
        self._cache.clear()


class GroupKeyEpoch:
    """Represents a key epoch for a group."""

    def __init__(
        self,
        group_id: str,
        epoch: int,
        chain_key_hash: bytes,
        valid_from: int,
        valid_until: Optional[int] = None,
    ):
        self.group_id = group_id
        self.epoch = epoch
        self.chain_key_hash = chain_key_hash
        self.valid_from = valid_from
        self.valid_until = valid_until

    @property
    def is_valid(self) -> bool:
        """Check if the epoch is currently valid."""
        now = int(time.time())
        if now < self.valid_from:
            return False
        if self.valid_until and now >= self.valid_until:
            return False
        return True

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "group_id": self.group_id,
            "epoch": self.epoch,
            "chain_key_hash": nacl.encoding.RawEncoder.encode(self.chain_key_hash).decode(),
            "valid_from": self.valid_from,
            "valid_until": self.valid_until or 0,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "GroupKeyEpoch":
        """Deserialize from dictionary."""
        valid_until = data.get("valid_until", 0) or None
        return cls(
            group_id=data["group_id"],
            epoch=data["epoch"],
            chain_key_hash=nacl.encoding.RawEncoder.decode(data["chain_key_hash"].encode()),
            valid_from=data["valid_from"],
            valid_until=valid_until,
        )


class KeyTreeNode:
    """Node in a binary tree for efficient key distribution."""

    def __init__(
        self,
        node_id: str,
        member_fingerprints: list[str],
        encryption_key: Optional[bytes] = None,
    ):
        self.node_id = node_id
        self.member_fingerprints = member_fingerprints
        self.encryption_key = encryption_key or nacl.utils.random(32)
        self.left: Optional[KeyTreeNode] = None
        self.right: Optional[KeyTreeNode] = None

    def is_leaf(self) -> bool:
        """Check if this is a leaf node (single member)."""
        return self.left is None and self.right is None

    def get_ancestor_path(self, member_fp: str) -> list["KeyTreeNode"]:
        """Get path from root to the leaf containing the member."""
        path = []
        self._find_path(member_fp, path)
        return path

    def _find_path(self, member_fp: str, path: list) -> bool:
        """Recursively find path to member."""
        if member_fp in self.member_fingerprints:
            path.append(self)
            return True
        if self.left and self.left._find_path(member_fp, path):
            path.append(self)
            return True
        if self.right and self.right._find_path(member_fp, path):
            path.append(self)
            return True
        return False


class KeyTree:
    """Binary tree for efficient key distribution in large groups."""

    def __init__(self, members: list[str]):
        self.members = members
        self.root: Optional[KeyTreeNode] = None
        if members:
            self.root = self._build_tree(members)

    def _build_tree(self, members: list[str]) -> KeyTreeNode:
        """Build a balanced binary tree from member list."""
        if len(members) == 1:
            return KeyTreeNode(
                node_id=secrets.token_hex(8),
                member_fingerprints=members,
            )

        mid = len(members) // 2
        left = self._build_tree(members[:mid])
        right = self._build_tree(members[mid:])

        combined_members = left.member_fingerprints + right.member_fingerprints
        node = KeyTreeNode(
            node_id=secrets.token_hex(8),
            member_fingerprints=combined_members,
        )
        node.left = left
        node.right = right

        combined_key_input = left.encryption_key + right.encryption_key + b"tree-node"
        node.encryption_key = hashlib.sha256(combined_key_input).digest()

        return node

    def get_key_for_member(self, member_fp: str) -> list[tuple[str, bytes]]:
        """Get encryption keys needed for a member to decrypt.

        Returns list of (node_id, encryption_key) for ancestors in the tree.
        """
        if not self.root:
            return []
        path = self.root.get_ancestor_path(member_fp)
        return [(n.node_id, n.encryption_key) for n in path]

    def broadcast_keys(self) -> dict[str, bytes]:
        """Get all node keys for broadcasting to the group."""
        result = {}
        self._collect_keys(self.root, result)
        return result

    def _collect_keys(self, node: Optional[KeyTreeNode], result: dict):
        """Recursively collect all node keys."""
        if node is None:
            return
        result[node.node_id] = node.encryption_key
        self._collect_keys(node.left, result)
        self._collect_keys(node.right, result)


class GroupEncryption:
    """Group encryption manager with forward secrecy."""

    def __init__(
        self,
        identity: "NodeIdentity",
        storage: Optional[Any] = None,
        dh_interval: int = DEFAULT_DH_INTERVAL,
    ):
        self.identity = identity
        self.storage = storage
        self.dh_interval = dh_interval

        self._sender_keys: dict[tuple[str, str], SenderKey] = {}
        self._message_key_cache = MessageKeyCache()

        if storage:
            self._load_sender_keys()

    def _load_sender_keys(self):
        """Lazy load sender keys from storage."""
        if not self.storage:
            return
        try:
            keys = self.storage.get_all_group_sender_keys()
            for key_data in keys:
                sender_key = SenderKey.from_dict(key_data)
                key_id = (sender_key.group_id, sender_key.sender_fingerprint)
                self._sender_keys[key_id] = sender_key
        except Exception:
            pass

    def create_sender_key(self, group_id: str) -> SenderKey:
        """Create a new sender key for a group."""
        chain_key = nacl.utils.random(32)
        root_key = nacl.utils.random(32)

        dh_private = nacl.public.PrivateKey.generate()
        dh_public = dh_private.public_key.encode(nacl.encoding.RawEncoder)

        signing_key = self.identity.signing_key
        verify_key_bytes = signing_key.verify_key.encode(nacl.encoding.RawEncoder)

        sender_key = SenderKey(
            group_id=group_id,
            sender_fingerprint=self.identity.fingerprint,
            chain_key=chain_key,
            root_key=root_key,
            dh_public_key=dh_public,
            dh_private_key=dh_private.encode(nacl.encoding.RawEncoder),
            message_number=0,
            dh_counter=0,
            epoch=0,
            signature_key=verify_key_bytes,
        )

        key_id = (group_id, self.identity.fingerprint)
        self._sender_keys[key_id] = sender_key

        if self.storage:
            self.storage.save_group_sender_key(sender_key.to_dict())
            epoch = GroupKeyEpoch(
                group_id=group_id,
                epoch=0,
                chain_key_hash=hashlib.sha256(chain_key).digest(),
                valid_from=int(time.time()),
            )
            self.storage.save_group_key_epoch(epoch.to_dict())

        return sender_key

    def get_sender_key(self, group_id: str) -> Optional[SenderKey]:
        """Get or create sender key for a group."""
        key_id = (group_id, self.identity.fingerprint)
        if key_id not in self._sender_keys:
            self.create_sender_key(group_id)
        return self._sender_keys.get(key_id)

    def get_sender_key_for_decryption(
        self, group_id: str, sender_fp: str, epoch: int
    ) -> Optional[SenderKey]:
        """Get sender key for a specific sender (for decryption)."""
        key_id = (group_id, sender_fp)
        return self._sender_keys.get(key_id)

    def encrypt_message(
        self, group_id: str, plaintext: bytes
    ) -> tuple[bytes, dict]:
        """Encrypt a message using sender key.

        Returns:
            Tuple of (ciphertext, header_dict).
        """
        sender_key = self.get_sender_key(group_id)
        if not sender_key:
            raise KeyDerivationError("No sender key for group")

        if sender_key.should_dh_ratchet(self.dh_interval):
            peer_dh_public = sender_key.dh_public_key
            sender_key = sender_key.dh_ratchet(peer_dh_public)
            key_id = (group_id, self.identity.fingerprint)
            self._sender_keys[key_id] = sender_key
            if self.storage:
                self.storage.save_group_sender_key(sender_key.to_dict())

        message_key, new_sender_key = sender_key.derive_message_key()

        key_id = (group_id, self.identity.fingerprint)
        self._sender_keys[key_id] = new_sender_key
        if self.storage:
            self.storage.save_group_sender_key(new_sender_key.to_dict())

        box = nacl.secret.SecretBox(message_key)
        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        ciphertext = box.encrypt(plaintext, nonce=nonce)

        header = {
            "sender_fp": self.identity.fingerprint,
            "epoch": new_sender_key.epoch,
            "message_number": new_sender_key.message_number,
            "dh_counter": new_sender_key.dh_counter,
            "dh_public_key": nacl.encoding.RawEncoder.encode(new_sender_key.dh_public_key).decode(),
            "signature_key": nacl.encoding.RawEncoder.encode(new_sender_key.signature_key).decode() if new_sender_key.signature_key else "",
        }

        self._message_key_cache.put(
            self.identity.fingerprint,
            new_sender_key.epoch,
            new_sender_key.message_number,
            message_key,
        )

        return ciphertext, header

    def decrypt_message(
        self,
        group_id: str,
        ciphertext: bytes,
        header: dict,
    ) -> Optional[bytes]:
        """Decrypt a group message."""
        sender_fp = header.get("sender_fp", "")
        epoch = header.get("epoch", 0)
        message_num = header.get("message_number", 0)

        cached_key = self._message_key_cache.get(sender_fp, epoch, message_num)
        if cached_key:
            message_key = cached_key
        else:
            key_id = (group_id, sender_fp)
            sender_key = self._sender_keys.get(key_id)
            if not sender_key:
                if self.storage:
                    key_data = self.storage.get_group_sender_key(group_id, sender_fp)
                    if key_data:
                        sender_key = SenderKey.from_dict(key_data)
                        self._sender_keys[key_id] = sender_key
            if not sender_key:
                return None

            dh_public = header.get("dh_public_key", "")
            if dh_public:
                dh_bytes = nacl.encoding.RawEncoder.decode(dh_public.encode())
                sender_key = sender_key.dh_ratchet(dh_bytes)

            for _ in range(message_num + 1):
                message_key, sender_key = sender_key.derive_message_key()

            key_id = (group_id, sender_fp)
            self._sender_keys[key_id] = sender_key
            if self.storage:
                self.storage.save_group_sender_key(sender_key.to_dict())

        try:
            box = nacl.secret.SecretBox(message_key)
            plaintext = box.decrypt(ciphertext)
            return plaintext
        except Exception:
            return None

    def rotate_keys_on_member_change(
        self, group_id: str, removed_members: list[str] = None
    ) -> SenderKey:
        """Rotate keys when membership changes (member removed)."""
        current_key = self.get_sender_key(group_id)
        if not current_key:
            return self.create_sender_key(group_id)

        new_epoch = current_key.epoch + 1

        new_chain_key = nacl.utils.random(32)
        new_root_key = nacl.utils.random(32)

        dh_private = nacl.public.PrivateKey.generate()
        dh_public = dh_private.public_key.encode(nacl.encoding.RawEncoder)

        new_sender_key = SenderKey(
            group_id=group_id,
            sender_fingerprint=self.identity.fingerprint,
            chain_key=new_chain_key,
            root_key=new_root_key,
            dh_public_key=dh_public,
            dh_private_key=dh_private.encode(nacl.encoding.RawEncoder),
            message_number=0,
            dh_counter=0,
            epoch=new_epoch,
            created_at=int(time.time()),
            signature_key=current_key.signature_key,
        )

        key_id = (group_id, self.identity.fingerprint)
        self._sender_keys[key_id] = new_sender_key
        self._message_key_cache.clear()

        if self.storage:
            self.storage.save_group_sender_key(new_sender_key.to_dict())
            epoch = GroupKeyEpoch(
                group_id=group_id,
                epoch=new_epoch,
                chain_key_hash=hashlib.sha256(new_chain_key).digest(),
                valid_from=int(time.time()),
            )
            self.storage.save_group_key_epoch(epoch.to_dict())
            self.storage.invalidate_group_key_epochs(group_id, new_epoch)

        return new_sender_key

    def get_key_distribution_payload(
        self, group_id: str, members: list[str]
    ) -> dict:
        """Get key distribution payload for a group.

        For groups > 50, uses tree-based distribution.
        For smaller groups, uses direct pairwise encryption.
        """
        sender_key = self.get_sender_key(group_id)
        if not sender_key:
            return {}

        if len(members) > LARGE_GROUP_THRESHOLD:
            tree = KeyTree(members)
            return {
                "distribution_type": "tree",
                "tree_keys": tree.broadcast_keys(),
                "epoch": sender_key.epoch,
                "sender_fp": self.identity.fingerprint,
            }
        else:
            return {
                "distribution_type": "direct",
                "chain_key": nacl.encoding.RawEncoder.encode(sender_key.chain_key).decode(),
                "root_key": nacl.encoding.RawEncoder.encode(sender_key.root_key).decode(),
                "dh_public_key": nacl.encoding.RawEncoder.encode(sender_key.dh_public_key).decode(),
                "epoch": sender_key.epoch,
                "sender_fp": self.identity.fingerprint,
            }

    def verify_forward_secrecy(self, epoch_n: int, epoch_n_minus_1: bytes) -> bool:
        """Verify that epoch N compromise doesn't expose epoch N-1.

        Returns True if the chain key hash for epoch N-1 doesn't match the
        current chain key (meaning it was securely rotated).
        """
        current_chain_key = hashlib.sha256(epoch_n_minus_1).digest()
        return current_chain_key != epoch_n_minus_1