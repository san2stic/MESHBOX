"""
MeshBox - Storage engine v4.
SQLite database for messages, profiles, metadata, Tor peers, and settings.
Features:
- WAL mode + secure_delete for concurrent access and security
- Connection pooling (thread-local reuse)
- Disappearing messages (auto-delete after read + timer)
- Message deduplication tracking (seen_messages table)
- Persistent nonce tracking for replay protection (seen_nonces table)
- Tor peer directory (tor_peers table)
- Delivery receipts tracking
- Key-value node settings (node_settings table)
- Message pagination
"""

import hashlib
import json
import os
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Optional


class StorageEngine:
    """Persistent storage management for messages, profiles, Tor peers, and settings."""

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        """Get a thread-local reusable connection."""
        conn = getattr(self._local, 'conn', None)
        if conn is not None:
            try:
                conn.execute("SELECT 1")
                return conn
            except sqlite3.ProgrammingError:
                pass
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA secure_delete=ON")
        self._local.conn = conn
        return conn

    @contextmanager
    def _transaction(self):
        conn = self._get_conn()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def close(self):
        """Close the thread-local connection."""
        conn = getattr(self._local, 'conn', None)
        if conn is not None:
            conn.close()
            self._local.conn = None

    def _init_db(self):
        """Initialize the database schema."""
        with self._transaction() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS profiles (
                    fingerprint TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    verify_key TEXT NOT NULL,
                    box_public_key TEXT NOT NULL,
                    bio TEXT DEFAULT '',
                    created_at INTEGER NOT NULL,
                    last_seen INTEGER NOT NULL,
                    is_local INTEGER DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS messages (
                    message_id TEXT PRIMARY KEY,
                    sender_fingerprint TEXT NOT NULL,
                    recipient_fingerprint TEXT NOT NULL,
                    encrypted_payload TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    ttl INTEGER DEFAULT 604800,
                    hop_count INTEGER DEFAULT 0,
                    delivered INTEGER DEFAULT 0,
                    read INTEGER DEFAULT 0,
                    proof_of_work INTEGER DEFAULT 0,
                    created_at INTEGER NOT NULL,
                    disappear_after_read INTEGER DEFAULT 0,
                    disappear_timer INTEGER DEFAULT 0,
                    read_at INTEGER DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS relay_messages (
                    message_id TEXT PRIMARY KEY,
                    sender_fingerprint TEXT NOT NULL,
                    recipient_fingerprint TEXT NOT NULL,
                    encrypted_payload TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    ttl INTEGER DEFAULT 604800,
                    hop_count INTEGER DEFAULT 0,
                    relayed_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS peer_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fingerprint TEXT NOT NULL,
                    connection_type TEXT NOT NULL,
                    ip_address TEXT,
                    seen_at INTEGER NOT NULL,
                    messages_exchanged INTEGER DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS shared_files (
                    file_id TEXT PRIMARY KEY,
                    sender_fingerprint TEXT NOT NULL,
                    recipient_fingerprint TEXT,
                    filename TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
                    mime_type TEXT DEFAULT 'application/octet-stream',
                    encrypted_path TEXT NOT NULL,
                    checksum TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    ttl INTEGER DEFAULT 604800,
                    downloaded INTEGER DEFAULT 0,
                    is_public INTEGER DEFAULT 0,
                    description TEXT DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS locations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fingerprint TEXT NOT NULL,
                    latitude REAL NOT NULL,
                    longitude REAL NOT NULL,
                    altitude REAL DEFAULT 0,
                    accuracy REAL DEFAULT 0,
                    label TEXT DEFAULT '',
                    shared INTEGER DEFAULT 0,
                    timestamp INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS sos_alerts (
                    alert_id TEXT PRIMARY KEY,
                    sender_fingerprint TEXT NOT NULL,
                    message TEXT NOT NULL,
                    latitude REAL,
                    longitude REAL,
                    severity TEXT DEFAULT 'high',
                    active INTEGER DEFAULT 1,
                    timestamp INTEGER NOT NULL,
                    ttl INTEGER DEFAULT 86400
                );

                CREATE TABLE IF NOT EXISTS channels (
                    channel_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT DEFAULT '',
                    creator_fingerprint TEXT NOT NULL,
                    is_public INTEGER DEFAULT 1,
                    created_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS channel_messages (
                    message_id TEXT PRIMARY KEY,
                    channel_id TEXT NOT NULL,
                    sender_fingerprint TEXT NOT NULL,
                    content TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    FOREIGN KEY (channel_id) REFERENCES channels(channel_id)
                );

                CREATE TABLE IF NOT EXISTS seen_messages (
                    message_id TEXT PRIMARY KEY,
                    first_seen INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS trust_scores (
                    fingerprint TEXT PRIMARY KEY,
                    score REAL DEFAULT 0.5,
                    successful_exchanges INTEGER DEFAULT 0,
                    failed_exchanges INTEGER DEFAULT 0,
                    last_updated INTEGER NOT NULL
                );

                -- v4: Persistent nonce tracking for replay protection
                CREATE TABLE IF NOT EXISTS seen_nonces (
                    nonce_id TEXT PRIMARY KEY,
                    first_seen INTEGER NOT NULL
                );

                -- v4: Tor peer directory
                CREATE TABLE IF NOT EXISTS tor_peers (
                    fingerprint TEXT PRIMARY KEY,
                    onion_address TEXT NOT NULL,
                    name TEXT DEFAULT '',
                    verify_key TEXT DEFAULT '',
                    box_public_key TEXT DEFAULT '',
                    last_seen INTEGER NOT NULL,
                    last_announced INTEGER DEFAULT 0,
                    is_directory_node INTEGER DEFAULT 0,
                    trust_score REAL DEFAULT 0.5
                );

                -- v4: Key-value node settings
                CREATE TABLE IF NOT EXISTS node_settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at INTEGER NOT NULL
                );

                -- v4: Delivery receipts
                CREATE TABLE IF NOT EXISTS delivery_receipts (
                    message_id TEXT PRIMARY KEY,
                    recipient_fingerprint TEXT NOT NULL,
                    delivered_at INTEGER NOT NULL,
                    ack_received INTEGER DEFAULT 0
                );

                -- Indexes
                CREATE INDEX IF NOT EXISTS idx_messages_recipient
                    ON messages(recipient_fingerprint);
                CREATE INDEX IF NOT EXISTS idx_messages_delivered
                    ON messages(delivered);
                CREATE INDEX IF NOT EXISTS idx_messages_timestamp
                    ON messages(timestamp);
                CREATE INDEX IF NOT EXISTS idx_relay_recipient
                    ON relay_messages(recipient_fingerprint);
                CREATE INDEX IF NOT EXISTS idx_relay_ttl
                    ON relay_messages(timestamp, ttl);
                CREATE INDEX IF NOT EXISTS idx_peer_log_fp
                    ON peer_log(fingerprint);
                CREATE INDEX IF NOT EXISTS idx_shared_files_sender
                    ON shared_files(sender_fingerprint);
                CREATE INDEX IF NOT EXISTS idx_shared_files_recipient
                    ON shared_files(recipient_fingerprint);
                CREATE INDEX IF NOT EXISTS idx_locations_fp
                    ON locations(fingerprint);
                CREATE INDEX IF NOT EXISTS idx_sos_active
                    ON sos_alerts(active, timestamp);
                CREATE INDEX IF NOT EXISTS idx_channel_messages_channel
                    ON channel_messages(channel_id, timestamp);
                CREATE INDEX IF NOT EXISTS idx_seen_messages_time
                    ON seen_messages(first_seen);
                CREATE INDEX IF NOT EXISTS idx_seen_nonces_time
                    ON seen_nonces(first_seen);
                CREATE INDEX IF NOT EXISTS idx_tor_peers_onion
                    ON tor_peers(onion_address);
                CREATE INDEX IF NOT EXISTS idx_tor_peers_seen
                    ON tor_peers(last_seen);
                CREATE INDEX IF NOT EXISTS idx_delivery_receipts_recipient
                    ON delivery_receipts(recipient_fingerprint);

                -- v5: Group encryption with sender keys
                CREATE TABLE IF NOT EXISTS groups (
                    group_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    creator_fingerprint TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    epoch INTEGER DEFAULT 1
                );

                CREATE TABLE IF NOT EXISTS group_members (
                    group_id TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    role TEXT DEFAULT 'member',
                    joined_at INTEGER NOT NULL,
                    PRIMARY KEY (group_id, fingerprint),
                    FOREIGN KEY (group_id) REFERENCES groups(group_id)
                );

                CREATE TABLE IF NOT EXISTS group_sender_keys (
                    group_id TEXT NOT NULL,
                    sender_fingerprint TEXT NOT NULL,
                    chain_key TEXT NOT NULL,
                    signature_key TEXT NOT NULL,
                    epoch INTEGER NOT NULL,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    PRIMARY KEY (group_id, sender_fingerprint),
                    FOREIGN KEY (group_id) REFERENCES groups(group_id)
                );

                CREATE INDEX IF NOT EXISTS idx_group_members_group
                    ON group_members(group_id);
                CREATE INDEX IF NOT EXISTS idx_group_sender_keys_group
                    ON group_sender_keys(group_id);
            """)
            # Migration: add columns if upgrading from older schema
            try:
                conn.execute("SELECT delivery_status FROM messages LIMIT 1")
            except sqlite3.OperationalError:
                conn.execute("ALTER TABLE messages ADD COLUMN delivery_status TEXT DEFAULT 'queued'")
            try:
                conn.execute("SELECT disappear_after_read FROM messages LIMIT 1")
            except sqlite3.OperationalError:
                conn.execute("ALTER TABLE messages ADD COLUMN disappear_after_read INTEGER DEFAULT 0")
            try:
                conn.execute("SELECT disappear_timer FROM messages LIMIT 1")
            except sqlite3.OperationalError:
                conn.execute("ALTER TABLE messages ADD COLUMN disappear_timer INTEGER DEFAULT 0")
            try:
                conn.execute("SELECT read_at FROM messages LIMIT 1")
            except sqlite3.OperationalError:
                conn.execute("ALTER TABLE messages ADD COLUMN read_at INTEGER DEFAULT 0")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_messages_delivery_status ON messages(delivery_status)")

    # === Node Settings ===

    def get_setting(self, key: str, default: str = "") -> str:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT value FROM node_settings WHERE key = ?", (key,)
        ).fetchone()
        return row["value"] if row else default

    def set_setting(self, key: str, value: str):
        with self._transaction() as conn:
            conn.execute("""
                INSERT INTO node_settings (key, value, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
            """, (key, value, int(time.time())))

    def get_all_settings(self) -> dict:
        conn = self._get_conn()
        rows = conn.execute("SELECT key, value FROM node_settings").fetchall()
        return {r["key"]: r["value"] for r in rows}

    # === Profiles ===

    def save_profile(self, profile: dict):
        """Save or update a profile."""
        with self._transaction() as conn:
            conn.execute("""
                INSERT INTO profiles (fingerprint, name, verify_key, box_public_key,
                                      bio, created_at, last_seen, is_local)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(fingerprint) DO UPDATE SET
                    name=excluded.name,
                    last_seen=excluded.last_seen,
                    bio=excluded.bio
            """, (
                profile["fingerprint"],
                profile["name"],
                profile["verify_key"],
                profile["box_public_key"],
                profile.get("bio", ""),
                profile.get("created_at", int(time.time())),
                int(time.time()),
                profile.get("is_local", 0),
            ))

    def get_profile(self, fingerprint: str) -> Optional[dict]:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM profiles WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()
        return dict(row) if row else None

    def get_local_profile(self) -> Optional[dict]:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM profiles WHERE is_local = 1"
        ).fetchone()
        return dict(row) if row else None

    def get_all_profiles(self) -> list:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM profiles ORDER BY last_seen DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    # === Messages ===

    def save_message(self, message: dict):
        with self._transaction() as conn:
            conn.execute("""
                INSERT OR IGNORE INTO messages
                (message_id, sender_fingerprint, recipient_fingerprint,
                 encrypted_payload, timestamp, ttl, hop_count, delivered,
                 read, proof_of_work, created_at,
                 disappear_after_read, disappear_timer, delivery_status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                message["message_id"],
                message["sender_fingerprint"],
                message["recipient_fingerprint"],
                json.dumps(message["encrypted_payload"]),
                message["timestamp"],
                message.get("ttl", 604800),
                message.get("hop_count", 0),
                message.get("delivered", 0),
                message.get("read", 0),
                message.get("proof_of_work", 0),
                int(time.time()),
                message.get("disappear_after_read", 0),
                message.get("disappear_timer", 0),
                message.get("delivery_status", "queued"),
            ))

    def get_inbox(self, fingerprint: str, limit: int = 0, offset: int = 0) -> list:
        conn = self._get_conn()
        if limit > 0:
            rows = conn.execute("""
                SELECT * FROM messages
                WHERE recipient_fingerprint = ? AND delivered = 1
                ORDER BY timestamp DESC LIMIT ? OFFSET ?
            """, (fingerprint, limit, offset)).fetchall()
        else:
            rows = conn.execute("""
                SELECT * FROM messages
                WHERE recipient_fingerprint = ? AND delivered = 1
                ORDER BY timestamp DESC
            """, (fingerprint,)).fetchall()
        return [dict(r) for r in rows]

    def get_inbox_count(self, fingerprint: str) -> int:
        conn = self._get_conn()
        return conn.execute(
            "SELECT COUNT(*) FROM messages WHERE recipient_fingerprint = ? AND delivered = 1",
            (fingerprint,)
        ).fetchone()[0]

    def get_outbox(self, fingerprint: str, limit: int = 0, offset: int = 0) -> list:
        conn = self._get_conn()
        if limit > 0:
            rows = conn.execute("""
                SELECT * FROM messages
                WHERE sender_fingerprint = ?
                ORDER BY timestamp DESC LIMIT ? OFFSET ?
            """, (fingerprint, limit, offset)).fetchall()
        else:
            rows = conn.execute("""
                SELECT * FROM messages
                WHERE sender_fingerprint = ?
                ORDER BY timestamp DESC
            """, (fingerprint,)).fetchall()
        return [dict(r) for r in rows]

    def get_outbox_count(self, fingerprint: str) -> int:
        conn = self._get_conn()
        return conn.execute(
            "SELECT COUNT(*) FROM messages WHERE sender_fingerprint = ?",
            (fingerprint,)
        ).fetchone()[0]

    def mark_delivered(self, message_id: str):
        with self._transaction() as conn:
            conn.execute(
                "UPDATE messages SET delivered = 1, delivery_status = 'delivered' WHERE message_id = ?",
                (message_id,),
            )

    def mark_read(self, message_id: str):
        with self._transaction() as conn:
            conn.execute(
                "UPDATE messages SET read = 1, read_at = ?, delivery_status = 'read' WHERE message_id = ?",
                (int(time.time()), message_id),
            )

    def update_delivery_status(self, message_id: str, status: str):
        with self._transaction() as conn:
            conn.execute(
                "UPDATE messages SET delivery_status = ? WHERE message_id = ?",
                (status, message_id),
            )

    # === Delivery Receipts ===

    def save_delivery_receipt(self, message_id: str, recipient_fingerprint: str):
        with self._transaction() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO delivery_receipts
                (message_id, recipient_fingerprint, delivered_at, ack_received)
                VALUES (?, ?, ?, 1)
            """, (message_id, recipient_fingerprint, int(time.time())))
            conn.execute(
                "UPDATE messages SET delivery_status = 'delivered' WHERE message_id = ?",
                (message_id,),
            )

    def get_delivery_receipt(self, message_id: str) -> Optional[dict]:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM delivery_receipts WHERE message_id = ?", (message_id,)
        ).fetchone()
        return dict(row) if row else None

    # === Relay messages (store-and-forward) ===

    def save_relay_message(self, message: dict):
        with self._transaction() as conn:
            conn.execute("""
                INSERT OR IGNORE INTO relay_messages
                (message_id, sender_fingerprint, recipient_fingerprint,
                 encrypted_payload, timestamp, ttl, hop_count, relayed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                message["message_id"],
                message["sender_fingerprint"],
                message["recipient_fingerprint"],
                json.dumps(message["encrypted_payload"]),
                message["timestamp"],
                message.get("ttl", 604800),
                message.get("hop_count", 0),
                int(time.time()),
            ))

    def get_relay_messages_for(self, fingerprint: str) -> list:
        conn = self._get_conn()
        now = int(time.time())
        rows = conn.execute("""
            SELECT * FROM relay_messages
            WHERE recipient_fingerprint = ?
            AND (timestamp + ttl) > ?
        """, (fingerprint, now)).fetchall()
        return [dict(r) for r in rows]

    def get_all_relay_messages(self) -> list:
        conn = self._get_conn()
        now = int(time.time())
        rows = conn.execute("""
            SELECT * FROM relay_messages
            WHERE (timestamp + ttl) > ?
        """, (now,)).fetchall()
        return [dict(r) for r in rows]

    def delete_relay_message(self, message_id: str):
        with self._transaction() as conn:
            conn.execute(
                "DELETE FROM relay_messages WHERE message_id = ?",
                (message_id,),
            )

    def cleanup_expired(self):
        now = int(time.time())
        with self._transaction() as conn:
            conn.execute(
                "DELETE FROM relay_messages WHERE (timestamp + ttl) < ?",
                (now,),
            )
            thirty_days_ago = now - (30 * 86400)
            conn.execute(
                "DELETE FROM messages WHERE timestamp < ? AND read = 1",
                (thirty_days_ago,),
            )
            conn.execute("""
                DELETE FROM messages
                WHERE disappear_after_read = 1
                AND read = 1
                AND read_at > 0
                AND (read_at + disappear_timer) < ?
            """, (now,))
            two_weeks_ago = now - (14 * 86400)
            conn.execute(
                "DELETE FROM seen_messages WHERE first_seen < ?",
                (two_weeks_ago,),
            )
            conn.execute(
                "DELETE FROM seen_nonces WHERE first_seen < ?",
                (two_weeks_ago,),
            )
            seven_days_ago = now - (7 * 86400)
            conn.execute(
                "DELETE FROM tor_peers WHERE last_seen < ? AND is_directory_node = 0",
                (seven_days_ago,),
            )

    # === Message deduplication ===

    def is_message_seen(self, message_id: str) -> bool:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT 1 FROM seen_messages WHERE message_id = ?", (message_id,)
        ).fetchone()
        return row is not None

    def get_relay_inventory_hashes(self) -> set:
        """Return a set of compact message_id hashes for efficient sync negotiation."""
        conn = self._get_conn()
        now = int(time.time())
        rows = conn.execute("""
            SELECT message_id FROM relay_messages
            WHERE (timestamp + ttl) > ?
        """, (now,)).fetchall()
        return {hashlib.sha256(r["message_id"].encode()).hexdigest()[:24] for r in rows}

    def get_seen_message_hashes(self, since: int = 0) -> set:
        """Return compact hashes of seen message IDs for dedup negotiation."""
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT message_id FROM seen_messages WHERE first_seen > ?
        """, (since,)).fetchall()
        return {hashlib.sha256(r["message_id"].encode()).hexdigest()[:24] for r in rows}

    def mark_message_seen(self, message_id: str):
        with self._transaction() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO seen_messages (message_id, first_seen) VALUES (?, ?)",
                (message_id, int(time.time())),
            )

    # === Persistent nonce tracking ===

    def is_nonce_seen(self, nonce_id: str) -> bool:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT 1 FROM seen_nonces WHERE nonce_id = ?", (nonce_id,)
        ).fetchone()
        return row is not None

    def mark_nonce_seen(self, nonce_id: str):
        with self._transaction() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO seen_nonces (nonce_id, first_seen) VALUES (?, ?)",
                (nonce_id, int(time.time())),
            )

    # === Trust scores ===

    def update_trust_score(self, fingerprint: str, success: bool):
        with self._transaction() as conn:
            existing = conn.execute(
                "SELECT * FROM trust_scores WHERE fingerprint = ?", (fingerprint,)
            ).fetchone()

            if existing:
                if success:
                    conn.execute("""
                        UPDATE trust_scores
                        SET score = MIN(1.0, score + 0.05),
                            successful_exchanges = successful_exchanges + 1,
                            last_updated = ?
                        WHERE fingerprint = ?
                    """, (int(time.time()), fingerprint))
                else:
                    conn.execute("""
                        UPDATE trust_scores
                        SET score = MAX(0.0, score - 0.1),
                            failed_exchanges = failed_exchanges + 1,
                            last_updated = ?
                        WHERE fingerprint = ?
                    """, (int(time.time()), fingerprint))
            else:
                score = 0.55 if success else 0.4
                conn.execute("""
                    INSERT INTO trust_scores
                    (fingerprint, score, successful_exchanges, failed_exchanges, last_updated)
                    VALUES (?, ?, ?, ?, ?)
                """, (fingerprint, score, 1 if success else 0, 0 if success else 1, int(time.time())))

    def get_trust_score(self, fingerprint: str) -> float:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT score FROM trust_scores WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()
        return row["score"] if row else 0.5

    # === Tor Peers ===

    def save_tor_peer(self, peer: dict):
        with self._transaction() as conn:
            conn.execute("""
                INSERT INTO tor_peers
                (fingerprint, onion_address, name, verify_key, box_public_key,
                 last_seen, last_announced, is_directory_node, trust_score)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(fingerprint) DO UPDATE SET
                    onion_address=excluded.onion_address,
                    name=excluded.name,
                    verify_key=excluded.verify_key,
                    box_public_key=excluded.box_public_key,
                    last_seen=excluded.last_seen,
                    last_announced=excluded.last_announced
            """, (
                peer["fingerprint"],
                peer["onion_address"],
                peer.get("name", ""),
                peer.get("verify_key", ""),
                peer.get("box_public_key", ""),
                int(time.time()),
                peer.get("last_announced", 0),
                peer.get("is_directory_node", 0),
                peer.get("trust_score", 0.5),
            ))

    def get_tor_peer(self, fingerprint: str) -> Optional[dict]:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM tor_peers WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()
        return dict(row) if row else None

    def get_tor_peer_by_onion(self, onion_address: str) -> Optional[dict]:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM tor_peers WHERE onion_address = ?", (onion_address,)
        ).fetchone()
        return dict(row) if row else None

    def get_all_tor_peers(self) -> list:
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT * FROM tor_peers ORDER BY last_seen DESC
        """).fetchall()
        return [dict(r) for r in rows]

    def get_active_tor_peers(self, max_age: int = 3600) -> list:
        conn = self._get_conn()
        cutoff = int(time.time()) - max_age
        rows = conn.execute("""
            SELECT * FROM tor_peers WHERE last_seen > ? ORDER BY trust_score DESC
        """, (cutoff,)).fetchall()
        return [dict(r) for r in rows]

    def get_directory_nodes(self) -> list:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM tor_peers WHERE is_directory_node = 1"
        ).fetchall()
        return [dict(r) for r in rows]

    def get_announced_peers_count(self) -> int:
        """Count peers that have announced to us (last_announced > 0)."""
        conn = self._get_conn()
        return conn.execute(
            "SELECT COUNT(*) FROM tor_peers WHERE last_announced > 0"
        ).fetchone()[0]

    def get_announced_peers(self, max_age: int = 7200) -> list:
        """Get peers that have announced to us recently."""
        conn = self._get_conn()
        cutoff = int(time.time()) - max_age
        rows = conn.execute(
            "SELECT * FROM tor_peers WHERE last_announced > ? ORDER BY last_announced DESC",
            (cutoff,)
        ).fetchall()
        return [dict(r) for r in rows]

    def delete_tor_peer(self, fingerprint: str):
        with self._transaction() as conn:
            conn.execute("DELETE FROM tor_peers WHERE fingerprint = ?", (fingerprint,))

    # === Peer log ===

    def log_peer(self, fingerprint: str, connection_type: str,
                 ip_address: str = "", messages_exchanged: int = 0):
        with self._transaction() as conn:
            conn.execute("""
                INSERT INTO peer_log (fingerprint, connection_type, ip_address,
                                      seen_at, messages_exchanged)
                VALUES (?, ?, ?, ?, ?)
            """, (fingerprint, connection_type, ip_address,
                  int(time.time()), messages_exchanged))

    def get_peer_history(self, fingerprint: str) -> list:
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT * FROM peer_log
            WHERE fingerprint = ?
            ORDER BY seen_at DESC LIMIT 100
        """, (fingerprint,)).fetchall()
        return [dict(r) for r in rows]

    def delete_message(self, message_id: str):
        with self._transaction() as conn:
            conn.execute("DELETE FROM messages WHERE message_id = ?", (message_id,))

    def delete_contact(self, fingerprint: str):
        with self._transaction() as conn:
            conn.execute(
                "DELETE FROM profiles WHERE fingerprint = ? AND is_local = 0",
                (fingerprint,),
            )

    def search_messages(self, fingerprint: str, query: str) -> list:
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT m.*, p.name as sender_name FROM messages m
            LEFT JOIN profiles p ON m.sender_fingerprint = p.fingerprint
            WHERE m.recipient_fingerprint = ? AND m.delivered = 1
            AND (p.name LIKE ? OR m.message_id LIKE ? OR m.sender_fingerprint LIKE ?)
            ORDER BY m.timestamp DESC
        """, (fingerprint, f"%{query}%", f"%{query}%", f"%{query}%")).fetchall()
        return [dict(r) for r in rows]

    def get_recent_peers(self, limit: int = 20) -> list:
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT pl.*, p.name as peer_name
            FROM peer_log pl
            LEFT JOIN profiles p ON pl.fingerprint = p.fingerprint
            ORDER BY pl.seen_at DESC
            LIMIT ?
        """, (limit,)).fetchall()
        return [dict(r) for r in rows]

    def get_message_by_id(self, message_id: str) -> Optional[dict]:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM messages WHERE message_id = ?", (message_id,)
        ).fetchone()
        return dict(row) if row else None

    def get_stats(self) -> dict:
        conn = self._get_conn()
        now = int(time.time())
        today_start = now - (now % 86400)
        stats = {
            "total_profiles": conn.execute("SELECT COUNT(*) FROM profiles WHERE is_local = 0").fetchone()[0],
            "total_messages": conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0],
            "inbox_messages": conn.execute(
                "SELECT COUNT(*) FROM messages WHERE delivered = 1"
            ).fetchone()[0],
            "sent_messages": conn.execute(
                "SELECT COUNT(*) FROM messages WHERE delivered = 0"
            ).fetchone()[0],
            "relay_messages": conn.execute("SELECT COUNT(*) FROM relay_messages").fetchone()[0],
            "unread_messages": conn.execute(
                "SELECT COUNT(*) FROM messages WHERE read = 0 AND delivered = 1"
            ).fetchone()[0],
            "total_peers_seen": conn.execute(
                "SELECT COUNT(DISTINCT fingerprint) FROM peer_log"
            ).fetchone()[0],
            "peers_today": conn.execute(
                "SELECT COUNT(DISTINCT fingerprint) FROM peer_log WHERE seen_at >= ?",
                (today_start,)
            ).fetchone()[0],
            "messages_today": conn.execute(
                "SELECT COUNT(*) FROM messages WHERE created_at >= ?",
                (today_start,)
            ).fetchone()[0],
            "db_size_bytes": os.path.getsize(str(self.db_path)) if self.db_path.exists() else 0,
            "total_files": conn.execute("SELECT COUNT(*) FROM shared_files").fetchone()[0],
            "active_sos": conn.execute("SELECT COUNT(*) FROM sos_alerts WHERE active = 1").fetchone()[0],
            "total_channels": conn.execute("SELECT COUNT(*) FROM channels").fetchone()[0],
            "total_locations": conn.execute("SELECT COUNT(*) FROM locations WHERE shared = 1").fetchone()[0],
            "tor_peers": conn.execute("SELECT COUNT(*) FROM tor_peers").fetchone()[0],
            "active_tor_peers": conn.execute(
                "SELECT COUNT(*) FROM tor_peers WHERE last_seen > ?",
                (now - 3600,)
            ).fetchone()[0],
            "tor_enabled": self.get_setting("tor_enabled", "true") == "true",
            "directory_node_enabled": self.get_setting("directory_node_enabled", "false") == "true",
            "directory_nodes": conn.execute(
                "SELECT COUNT(*) FROM tor_peers WHERE is_directory_node = 1"
            ).fetchone()[0],
            "announced_peers": conn.execute(
                "SELECT COUNT(*) FROM tor_peers WHERE last_announced > 0"
            ).fetchone()[0],
        }
        return stats

    # === Shared files ===

    def save_shared_file(self, file_data: dict):
        with self._transaction() as conn:
            conn.execute("""
                INSERT OR IGNORE INTO shared_files
                (file_id, sender_fingerprint, recipient_fingerprint, filename,
                 file_size, mime_type, encrypted_path, checksum, timestamp,
                 ttl, downloaded, is_public, description)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                file_data["file_id"],
                file_data["sender_fingerprint"],
                file_data.get("recipient_fingerprint", ""),
                file_data["filename"],
                file_data["file_size"],
                file_data.get("mime_type", "application/octet-stream"),
                file_data["encrypted_path"],
                file_data["checksum"],
                file_data["timestamp"],
                file_data.get("ttl", 604800),
                0,
                file_data.get("is_public", 0),
                file_data.get("description", ""),
            ))

    def get_my_files(self, fingerprint: str) -> list:
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT sf.*, p.name as recipient_name FROM shared_files sf
            LEFT JOIN profiles p ON sf.recipient_fingerprint = p.fingerprint
            WHERE sf.sender_fingerprint = ?
            ORDER BY sf.timestamp DESC
        """, (fingerprint,)).fetchall()
        return [dict(r) for r in rows]

    def get_files_for_me(self, fingerprint: str) -> list:
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT sf.*, p.name as sender_name FROM shared_files sf
            LEFT JOIN profiles p ON sf.sender_fingerprint = p.fingerprint
            WHERE sf.recipient_fingerprint = ? OR sf.is_public = 1
            ORDER BY sf.timestamp DESC
        """, (fingerprint,)).fetchall()
        return [dict(r) for r in rows]

    def get_public_files(self) -> list:
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT sf.*, p.name as sender_name FROM shared_files sf
            LEFT JOIN profiles p ON sf.sender_fingerprint = p.fingerprint
            WHERE sf.is_public = 1
            ORDER BY sf.timestamp DESC
        """).fetchall()
        return [dict(r) for r in rows]

    def get_file_by_id(self, file_id: str) -> Optional[dict]:
        conn = self._get_conn()
        row = conn.execute("SELECT * FROM shared_files WHERE file_id = ?", (file_id,)).fetchone()
        return dict(row) if row else None

    def delete_shared_file(self, file_id: str):
        with self._transaction() as conn:
            conn.execute("DELETE FROM shared_files WHERE file_id = ?", (file_id,))

    # === Locations ===

    def save_location(self, location: dict):
        with self._transaction() as conn:
            conn.execute("""
                INSERT INTO locations
                (fingerprint, latitude, longitude, altitude, accuracy, label, shared, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                location["fingerprint"],
                location["latitude"],
                location["longitude"],
                location.get("altitude", 0),
                location.get("accuracy", 0),
                location.get("label", ""),
                location.get("shared", 0),
                int(time.time()),
            ))

    def get_my_locations(self, fingerprint: str) -> list:
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT * FROM locations WHERE fingerprint = ?
            ORDER BY timestamp DESC LIMIT 100
        """, (fingerprint,)).fetchall()
        return [dict(r) for r in rows]

    def get_shared_locations(self) -> list:
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT l.*, p.name as peer_name FROM locations l
            LEFT JOIN profiles p ON l.fingerprint = p.fingerprint
            WHERE l.shared = 1
            ORDER BY l.timestamp DESC
        """).fetchall()
        return [dict(r) for r in rows]

    def get_latest_locations(self) -> list:
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT l.*, p.name as peer_name FROM locations l
            LEFT JOIN profiles p ON l.fingerprint = p.fingerprint
            WHERE l.shared = 1 AND l.id IN (
                SELECT MAX(id) FROM locations WHERE shared = 1 GROUP BY fingerprint
            )
            ORDER BY l.timestamp DESC
        """).fetchall()
        return [dict(r) for r in rows]

    # === SOS alerts ===

    def save_sos_alert(self, alert: dict):
        with self._transaction() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO sos_alerts
                (alert_id, sender_fingerprint, message, latitude, longitude,
                 severity, active, timestamp, ttl)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert["alert_id"],
                alert["sender_fingerprint"],
                alert["message"],
                alert.get("latitude"),
                alert.get("longitude"),
                alert.get("severity", "high"),
                1,
                alert["timestamp"],
                alert.get("ttl", 86400),
            ))

    def get_active_sos(self) -> list:
        conn = self._get_conn()
        now = int(time.time())
        rows = conn.execute("""
            SELECT sa.*, p.name as sender_name FROM sos_alerts sa
            LEFT JOIN profiles p ON sa.sender_fingerprint = p.fingerprint
            WHERE sa.active = 1 AND (sa.timestamp + sa.ttl) > ?
            ORDER BY sa.timestamp DESC
        """, (now,)).fetchall()
        return [dict(r) for r in rows]

    def get_all_sos(self) -> list:
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT sa.*, p.name as sender_name FROM sos_alerts sa
            LEFT JOIN profiles p ON sa.sender_fingerprint = p.fingerprint
            ORDER BY sa.timestamp DESC LIMIT 50
        """).fetchall()
        return [dict(r) for r in rows]

    def deactivate_sos(self, alert_id: str):
        with self._transaction() as conn:
            conn.execute("UPDATE sos_alerts SET active = 0 WHERE alert_id = ?", (alert_id,))

    # === Channels ===

    def create_channel(self, channel: dict):
        with self._transaction() as conn:
            conn.execute("""
                INSERT OR IGNORE INTO channels
                (channel_id, name, description, creator_fingerprint, is_public, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                channel["channel_id"],
                channel["name"],
                channel.get("description", ""),
                channel["creator_fingerprint"],
                channel.get("is_public", 1),
                int(time.time()),
            ))

    def get_channels(self) -> list:
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT c.*, p.name as creator_name,
                   (SELECT COUNT(*) FROM channel_messages WHERE channel_id = c.channel_id) as msg_count
            FROM channels c
            LEFT JOIN profiles p ON c.creator_fingerprint = p.fingerprint
            WHERE c.is_public = 1
            ORDER BY c.created_at DESC
        """).fetchall()
        return [dict(r) for r in rows]

    def get_channel(self, channel_id: str) -> Optional[dict]:
        conn = self._get_conn()
        row = conn.execute("""
            SELECT c.*, p.name as creator_name FROM channels c
            LEFT JOIN profiles p ON c.creator_fingerprint = p.fingerprint
            WHERE c.channel_id = ?
        """, (channel_id,)).fetchone()
        return dict(row) if row else None

    def post_channel_message(self, msg: dict):
        with self._transaction() as conn:
            conn.execute("""
                INSERT INTO channel_messages
                (message_id, channel_id, sender_fingerprint, content, timestamp)
                VALUES (?, ?, ?, ?, ?)
            """, (
                msg["message_id"],
                msg["channel_id"],
                msg["sender_fingerprint"],
                msg["content"],
                int(time.time()),
            ))

    def get_channel_messages(self, channel_id: str, limit: int = 50) -> list:
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT cm.*, p.name as sender_name FROM channel_messages cm
            LEFT JOIN profiles p ON cm.sender_fingerprint = p.fingerprint
            WHERE cm.channel_id = ?
            ORDER BY cm.timestamp DESC LIMIT ?
        """, (channel_id, limit)).fetchall()
        return [dict(r) for r in rows]

    def delete_channel(self, channel_id: str):
        with self._transaction() as conn:
            conn.execute("DELETE FROM channel_messages WHERE channel_id = ?", (channel_id,))
            conn.execute("DELETE FROM channels WHERE channel_id = ?", (channel_id,))

    # === Groups with Sender Keys ===

    def create_group(self, group_id: str, name: str, creator_fingerprint: str):
        with self._transaction() as conn:
            now = int(time.time())
            conn.execute("""
                INSERT INTO groups (group_id, name, creator_fingerprint, created_at, updated_at, epoch)
                VALUES (?, ?, ?, ?, ?, 1)
            """, (group_id, name, creator_fingerprint, now, now))
            conn.execute("""
                INSERT INTO group_members (group_id, fingerprint, role, joined_at)
                VALUES (?, ?, 'admin', ?)
            """, (group_id, creator_fingerprint, now))

    def get_group(self, group_id: str) -> Optional[dict]:
        conn = self._get_conn()
        row = conn.execute("SELECT * FROM groups WHERE group_id = ?", (group_id,)).fetchone()
        return dict(row) if row else None

    def get_groups(self) -> list:
        conn = self._get_conn()
        rows = conn.execute("SELECT * FROM groups ORDER BY updated_at DESC").fetchall()
        return [dict(r) for r in rows]

    def update_group_epoch(self, group_id: str, epoch: int):
        with self._transaction() as conn:
            conn.execute(
                "UPDATE groups SET epoch = ?, updated_at = ? WHERE group_id = ?",
                (epoch, int(time.time()), group_id),
            )

    def add_group_member(self, group_id: str, fingerprint: str, role: str = "member"):
        with self._transaction() as conn:
            conn.execute("""
                INSERT OR IGNORE INTO group_members (group_id, fingerprint, role, joined_at)
                VALUES (?, ?, ?, ?)
            """, (group_id, fingerprint, role, int(time.time())))

    def remove_group_member(self, group_id: str, fingerprint: str) -> bool:
        with self._transaction() as conn:
            result = conn.execute(
                "DELETE FROM group_members WHERE group_id = ? AND fingerprint = ?",
                (group_id, fingerprint),
            )
            return result.rowcount > 0

    def get_group_members(self, group_id: str) -> list:
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT * FROM group_members WHERE group_id = ? ORDER BY joined_at
        """, (group_id,)).fetchall()
        return [dict(r) for r in rows]

    def save_sender_key(self, group_id: str, sender_fingerprint: str,
                      chain_key: str, signature_key: str, epoch: int):
        with self._transaction() as conn:
            now = int(time.time())
            conn.execute("""
                INSERT OR REPLACE INTO group_sender_keys
                (group_id, sender_fingerprint, chain_key, signature_key, epoch, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (group_id, sender_fingerprint, chain_key, signature_key, epoch, now, now))

    def get_sender_key(self, group_id: str, sender_fingerprint: str) -> Optional[dict]:
        conn = self._get_conn()
        row = conn.execute("""
            SELECT * FROM group_sender_keys WHERE group_id = ? AND sender_fingerprint = ?
        """, (group_id, sender_fingerprint)).fetchone()
        return dict(row) if row else None

    def get_group_sender_keys(self, group_id: str) -> list:
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT * FROM group_sender_keys WHERE group_id = ?
        """, (group_id,)).fetchall()
        return [dict(r) for r in rows]

    def delete_sender_key(self, group_id: str, sender_fingerprint: str):
        with self._transaction() as conn:
            conn.execute(
                "DELETE FROM group_sender_keys WHERE group_id = ? AND sender_fingerprint = ?",
                (group_id, sender_fingerprint),
            )
