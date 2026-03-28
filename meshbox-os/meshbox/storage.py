"""
MeshBox - Storage engine.
SQLite database for messages, profiles, and metadata.
"""

import json
import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Optional


class StorageEngine:
    """Persistent storage management for messages and profiles."""

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
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
        finally:
            conn.close()

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
                    created_at INTEGER NOT NULL
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

                CREATE INDEX IF NOT EXISTS idx_messages_recipient
                    ON messages(recipient_fingerprint);
                CREATE INDEX IF NOT EXISTS idx_messages_delivered
                    ON messages(delivered);
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
            """)

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
        """Get a profile by fingerprint."""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM profiles WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()
        conn.close()
        return dict(row) if row else None

    def get_local_profile(self) -> Optional[dict]:
        """Get the local profile."""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM profiles WHERE is_local = 1"
        ).fetchone()
        conn.close()
        return dict(row) if row else None

    def get_all_profiles(self) -> list:
        """Get all known profiles."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM profiles ORDER BY last_seen DESC"
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    # === Messages ===

    def save_message(self, message: dict):
        """Save a message (received or sent)."""
        with self._transaction() as conn:
            conn.execute("""
                INSERT OR IGNORE INTO messages
                (message_id, sender_fingerprint, recipient_fingerprint,
                 encrypted_payload, timestamp, ttl, hop_count, delivered,
                 read, proof_of_work, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            ))

    def get_inbox(self, fingerprint: str) -> list:
        """Get received messages for a user."""
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT * FROM messages
            WHERE recipient_fingerprint = ? AND delivered = 1
            ORDER BY timestamp DESC
        """, (fingerprint,)).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_outbox(self, fingerprint: str) -> list:
        """Get sent messages."""
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT * FROM messages
            WHERE sender_fingerprint = ?
            ORDER BY timestamp DESC
        """, (fingerprint,)).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def mark_delivered(self, message_id: str):
        with self._transaction() as conn:
            conn.execute(
                "UPDATE messages SET delivered = 1 WHERE message_id = ?",
                (message_id,),
            )

    def mark_read(self, message_id: str):
        with self._transaction() as conn:
            conn.execute(
                "UPDATE messages SET read = 1 WHERE message_id = ?",
                (message_id,),
            )

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
        conn.close()
        return [dict(r) for r in rows]

    def get_all_relay_messages(self) -> list:
        conn = self._get_conn()
        now = int(time.time())
        rows = conn.execute("""
            SELECT * FROM relay_messages
            WHERE (timestamp + ttl) > ?
        """, (now,)).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def delete_relay_message(self, message_id: str):
        with self._transaction() as conn:
            conn.execute(
                "DELETE FROM relay_messages WHERE message_id = ?",
                (message_id,),
            )

    def cleanup_expired(self):
        """Clean up expired messages."""
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
        conn.close()
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
        conn.close()
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
        conn.close()
        return [dict(r) for r in rows]

    def get_message_by_id(self, message_id: str) -> Optional[dict]:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM messages WHERE message_id = ?", (message_id,)
        ).fetchone()
        conn.close()
        return dict(row) if row else None

    def get_stats(self) -> dict:
        """Node statistics."""
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
        }
        conn.close()
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
        conn.close()
        return [dict(r) for r in rows]

    def get_files_for_me(self, fingerprint: str) -> list:
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT sf.*, p.name as sender_name FROM shared_files sf
            LEFT JOIN profiles p ON sf.sender_fingerprint = p.fingerprint
            WHERE sf.recipient_fingerprint = ? OR sf.is_public = 1
            ORDER BY sf.timestamp DESC
        """, (fingerprint,)).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_public_files(self) -> list:
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT sf.*, p.name as sender_name FROM shared_files sf
            LEFT JOIN profiles p ON sf.sender_fingerprint = p.fingerprint
            WHERE sf.is_public = 1
            ORDER BY sf.timestamp DESC
        """).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_file_by_id(self, file_id: str) -> Optional[dict]:
        conn = self._get_conn()
        row = conn.execute("SELECT * FROM shared_files WHERE file_id = ?", (file_id,)).fetchone()
        conn.close()
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
        conn.close()
        return [dict(r) for r in rows]

    def get_shared_locations(self) -> list:
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT l.*, p.name as peer_name FROM locations l
            LEFT JOIN profiles p ON l.fingerprint = p.fingerprint
            WHERE l.shared = 1
            ORDER BY l.timestamp DESC
        """).fetchall()
        conn.close()
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
        conn.close()
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
        conn.close()
        return [dict(r) for r in rows]

    def get_all_sos(self) -> list:
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT sa.*, p.name as sender_name FROM sos_alerts sa
            LEFT JOIN profiles p ON sa.sender_fingerprint = p.fingerprint
            ORDER BY sa.timestamp DESC LIMIT 50
        """).fetchall()
        conn.close()
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
        conn.close()
        return [dict(r) for r in rows]

    def get_channel(self, channel_id: str) -> Optional[dict]:
        conn = self._get_conn()
        row = conn.execute("""
            SELECT c.*, p.name as creator_name FROM channels c
            LEFT JOIN profiles p ON c.creator_fingerprint = p.fingerprint
            WHERE c.channel_id = ?
        """, (channel_id,)).fetchone()
        conn.close()
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
        conn.close()
        return [dict(r) for r in rows]

    def delete_channel(self, channel_id: str):
        with self._transaction() as conn:
            conn.execute("DELETE FROM channel_messages WHERE channel_id = ?", (channel_id,))
            conn.execute("DELETE FROM channels WHERE channel_id = ?", (channel_id,))
