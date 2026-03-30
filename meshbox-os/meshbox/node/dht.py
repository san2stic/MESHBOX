"""
DHT — Simplified Kademlia Distributed Hash Table.

Provides decentralised key-value storage and peer discovery.
Node distance is measured by XOR of SHA3-256 node IDs.

Each node maintains K-buckets (one per bit of the ID space) and supports
the core Kademlia RPCs: FIND_NODE, FIND_VALUE, STORE.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger("meshbox.node.dht")

K = 20        # replication factor / bucket size
ALPHA = 3     # parallelism factor for lookups
ID_BITS = 256 # SHA3-256


def _xor_distance(a: bytes, b: bytes) -> int:
    """Compute the XOR-distance between two 32-byte IDs."""
    return int.from_bytes(a, "big") ^ int.from_bytes(b, "big")


def _bucket_index(distance: int) -> int:
    """Return the bucket index (0-255) for a given XOR distance."""
    if distance == 0:
        return 0
    return distance.bit_length() - 1


@dataclass
class KademliaEntry:
    """A contact stored in a K-bucket."""

    node_id: str
    node_id_raw: bytes  # 32-byte raw hash
    onion_address: str
    last_seen: float = field(default_factory=time.time)


@dataclass
class StoredValue:
    """A value stored in the DHT."""

    key: str
    value: Any
    stored_at: float = field(default_factory=time.time)
    ttl: float = 3600  # 1 hour default


class KademliaNode:
    """Simplified Kademlia DHT node.

    The node ID is a 32-byte SHA3-256 hash of the Ed25519 public key.
    """

    def __init__(
        self,
        node_id: str,
        onion_address: str,
    ) -> None:
        self.node_id = node_id
        self.node_id_raw = bytes.fromhex(node_id)
        self.onion_address = onion_address

        # K-buckets: list of K lists, index = bit-length of XOR distance
        self._buckets: list[list[KademliaEntry]] = [[] for _ in range(ID_BITS)]

        # Local key-value store
        self._store: dict[str, StoredValue] = {}

        # RPC callback — set by daemon
        self._rpc_send: Optional[Any] = None

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def set_rpc_callback(self, cb) -> None:
        """Register the async function that sends DHT RPCs to remote nodes."""
        self._rpc_send = cb

    # ------------------------------------------------------------------
    # Routing table
    # ------------------------------------------------------------------

    def add_contact(
        self,
        node_id: str,
        onion_address: str,
    ) -> None:
        """Add or refresh a contact in the appropriate K-bucket."""
        if node_id == self.node_id:
            return

        raw = bytes.fromhex(node_id)
        dist = _xor_distance(self.node_id_raw, raw)
        idx = _bucket_index(dist)
        bucket = self._buckets[idx]

        # Check if already in bucket
        for i, entry in enumerate(bucket):
            if entry.node_id == node_id:
                entry.last_seen = time.time()
                entry.onion_address = onion_address
                # Move to tail (most recently seen)
                bucket.append(bucket.pop(i))
                return

        if len(bucket) < K:
            bucket.append(
                KademliaEntry(
                    node_id=node_id,
                    node_id_raw=raw,
                    onion_address=onion_address,
                )
            )
        else:
            # Bucket full — evict head (least recently seen) if it's stale
            oldest = bucket[0]
            if time.time() - oldest.last_seen > 600:
                bucket.pop(0)
                bucket.append(
                    KademliaEntry(
                        node_id=node_id,
                        node_id_raw=raw,
                        onion_address=onion_address,
                    )
                )

    def find_closest(self, target_id: str, count: int = K) -> list[KademliaEntry]:
        """Return the *count* closest contacts to *target_id* (by XOR)."""
        target_raw = bytes.fromhex(target_id)
        all_contacts: list[tuple[int, KademliaEntry]] = []
        for bucket in self._buckets:
            for entry in bucket:
                dist = _xor_distance(target_raw, entry.node_id_raw)
                all_contacts.append((dist, entry))
        all_contacts.sort(key=lambda x: x[0])
        return [e for _, e in all_contacts[:count]]

    # ------------------------------------------------------------------
    # Core Kademlia Operations
    # ------------------------------------------------------------------

    async def find_node(self, target_id: str) -> list[dict]:
        """Iterative FIND_NODE: find the K closest nodes to *target_id*.

        Returns a list of dicts with ``node_id`` and ``onion_address``.
        """
        closest = self.find_closest(target_id, K)
        queried: set[str] = set()
        result: dict[str, KademliaEntry] = {
            e.node_id: e for e in closest
        }

        for _ in range(5):  # max iterations
            # Pick ALPHA unqueried closest nodes
            candidates = sorted(
                [e for e in result.values() if e.node_id not in queried],
                key=lambda e: _xor_distance(
                    bytes.fromhex(target_id), e.node_id_raw
                ),
            )[:ALPHA]

            if not candidates:
                break

            for entry in candidates:
                queried.add(entry.node_id)
                if self._rpc_send:
                    try:
                        response = await self._rpc_send(
                            entry.onion_address,
                            "find_node",
                            {"target_id": target_id},
                        )
                        for peer in response.get("nodes", []):
                            nid = peer["node_id"]
                            if nid not in result:
                                self.add_contact(nid, peer["onion_address"])
                                result[nid] = KademliaEntry(
                                    node_id=nid,
                                    node_id_raw=bytes.fromhex(nid),
                                    onion_address=peer["onion_address"],
                                )
                    except Exception as exc:
                        logger.debug("find_node RPC to %s failed: %s", entry.node_id[:12], exc)

        # Return sorted by distance
        target_raw = bytes.fromhex(target_id)
        sorted_result = sorted(
            result.values(),
            key=lambda e: _xor_distance(target_raw, e.node_id_raw),
        )
        return [
            {"node_id": e.node_id, "onion_address": e.onion_address}
            for e in sorted_result[:K]
        ]

    async def store(self, key: str, value: Any, ttl: float = 3600) -> None:
        """Store a key-value pair locally and replicate to K closest nodes."""
        key_hash = hashlib.sha3_256(key.encode()).hexdigest()

        # Store locally
        self._store[key_hash] = StoredValue(
            key=key, value=value, ttl=ttl
        )

        # Replicate to closest nodes
        closest = self.find_closest(key_hash, K)
        for entry in closest:
            if self._rpc_send:
                try:
                    await self._rpc_send(
                        entry.onion_address,
                        "store",
                        {"key": key, "key_hash": key_hash, "value": value, "ttl": ttl},
                    )
                except Exception:
                    pass

    async def find_value(self, key: str) -> Optional[Any]:
        """Look up a value in the DHT.  Returns the value or None."""
        key_hash = hashlib.sha3_256(key.encode()).hexdigest()

        # Check local store
        local = self._store.get(key_hash)
        if local and (time.time() - local.stored_at) < local.ttl:
            return local.value

        # Query closest nodes
        closest = self.find_closest(key_hash, K)
        for entry in closest:
            if self._rpc_send:
                try:
                    response = await self._rpc_send(
                        entry.onion_address,
                        "find_value",
                        {"key": key, "key_hash": key_hash},
                    )
                    if "value" in response:
                        # Cache locally
                        self._store[key_hash] = StoredValue(
                            key=key, value=response["value"]
                        )
                        return response["value"]
                except Exception:
                    pass

        return None

    # ------------------------------------------------------------------
    # RPC handlers (called by the SANP server)
    # ------------------------------------------------------------------

    def handle_find_node(self, target_id: str) -> list[dict]:
        """Handle an incoming FIND_NODE request."""
        closest = self.find_closest(target_id, K)
        return [
            {"node_id": e.node_id, "onion_address": e.onion_address}
            for e in closest
        ]

    def handle_store(
        self, key: str, key_hash: str, value: Any, ttl: float = 3600
    ) -> bool:
        """Handle an incoming STORE request."""
        # Verify key_hash matches
        expected = hashlib.sha3_256(key.encode()).hexdigest()
        if key_hash != expected:
            return False
        self._store[key_hash] = StoredValue(key=key, value=value, ttl=ttl)
        return True

    def handle_find_value(self, key_hash: str) -> Optional[Any]:
        """Handle an incoming FIND_VALUE request."""
        entry = self._store.get(key_hash)
        if entry and (time.time() - entry.stored_at) < entry.ttl:
            return entry.value
        return None

    # ------------------------------------------------------------------
    # Maintenance
    # ------------------------------------------------------------------

    def cleanup_expired(self) -> int:
        """Remove expired stored values."""
        now = time.time()
        expired = [
            kh
            for kh, sv in self._store.items()
            if (now - sv.stored_at) > sv.ttl
        ]
        for kh in expired:
            del self._store[kh]
        return len(expired)

    @property
    def total_contacts(self) -> int:
        return sum(len(b) for b in self._buckets)

    @property
    def stored_values(self) -> int:
        return len(self._store)
