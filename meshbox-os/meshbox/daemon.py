"""
MeshBox Daemon (meshboxd)
Main daemon that coordinates all components:
- Network discovery (WiFi + Bluetooth)
- Profile and message exchange
- Store-and-forward protocol
- Periodic cleanup
"""

import asyncio
import base64
import json
import logging
import os
import signal
import sys
import time
import uuid
from pathlib import Path
from typing import Optional

from meshbox.config import DATA_DIR
from meshbox.crypto import Identity, CryptoEngine
from meshbox.files import FileManager
from meshbox.network import NetworkManager, PeerInfo, MessageTransport
from meshbox.profiles import ProfileManager
from meshbox.storage import StorageEngine


class MeshBoxDaemon:
    """Main MeshBox daemon - core of the decentralized messaging system."""

    def __init__(self, data_dir: Path = None):
        self.data_dir = data_dir or DATA_DIR
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.storage = StorageEngine(self.data_dir / "meshbox.db")
        self.profile_mgr = ProfileManager(self.storage, self.data_dir / "keys")
        self.file_mgr: Optional[FileManager] = None
        self.network: Optional[NetworkManager] = None
        self._running = False

    @property
    def is_initialized(self) -> bool:
        return self.profile_mgr.is_initialized

    async def start(self):
        """Start the MeshBox daemon."""
        if not self.is_initialized:
            logging.error("Profile not initialized. Run 'meshbox profile create' first.")
            return

        profile = self.profile_mgr.export_profile_for_sharing()
        logging.info("Starting MeshBox daemon - %s (%s)",
                     profile["name"], profile["fingerprint"])

        self.file_mgr = FileManager(
            self.storage, self.profile_mgr.identity,
            self.data_dir / "files"
        )

        self.network = NetworkManager(profile)
        self.network.on_peer_discovered = self._on_peer_discovered
        self.network.on_message_received = self._on_message_received
        self.network.transport.on_sync_request = self._handle_sync_request

        self._running = True

        tasks = [
            asyncio.create_task(self.network.start()),
            asyncio.create_task(self._periodic_sync()),
            asyncio.create_task(self._periodic_cleanup()),
        ]

        loop = asyncio.get_event_loop()
        if sys.platform != "win32":
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(sig, lambda: asyncio.create_task(self.stop()))

        logging.info("MeshBox daemon started - waiting for peers...")

        try:
            await asyncio.gather(*tasks, return_exceptions=True)
        except asyncio.CancelledError:
            pass

    async def stop(self):
        logging.info("Stopping MeshBox daemon...")
        self._running = False
        if self.network:
            self.network.stop()

    async def _on_peer_discovered(self, peer: PeerInfo):
        logging.info("New peer discovered: %s via %s",
                     peer.fingerprint, peer.connection_type)

        if peer.profile_data:
            self.profile_mgr.add_contact_from_discovery(peer.profile_data)

        self.storage.log_peer(
            peer.fingerprint, peer.connection_type, peer.address
        )

        await self._sync_with_peer(peer)

    async def _on_message_received(self, message: dict):
        msg_type = message.get("type", "message")

        if msg_type == "sos":
            logging.info("SOS alert received from %s", message.get("sender_fingerprint", "???"))
            self.storage.save_sos_alert(message)
            return
        if msg_type == "location":
            logging.info("Location received from %s", message.get("fingerprint", "???"))
            self.storage.save_location(message)
            return
        if msg_type == "channel":
            logging.info("Channel message received: %s", message.get("channel_id", "???"))
            channel = self.storage.get_channel(message.get("channel_id", ""))
            if channel:
                self.storage.post_channel_message(message)
            return
        if msg_type == "channel_create":
            logging.info("Channel creation received: %s", message.get("name", "???"))
            existing = self.storage.get_channel(message.get("channel_id", ""))
            if not existing:
                self.storage.create_channel(message)
            return
        if msg_type == "file":
            logging.info("File received: %s from %s",
                         message.get("filename", "???"),
                         message.get("sender_fingerprint", "???"))
            self._save_received_file(message)
            return

        msg_id = message.get("message_id", "???")
        recipient = message.get("recipient_fingerprint", "")
        sender = message.get("sender_fingerprint", "")

        local_profile = self.profile_mgr.get_local_profile()
        if not local_profile:
            return

        my_fingerprint = local_profile["fingerprint"]

        if recipient == "__SOS_BROADCAST__":
            logging.info("SOS broadcast received from %s", sender)
            self.storage.save_relay_message(message)
            return

        if recipient == my_fingerprint:
            logging.info("Message received from %s (id: %s)", sender, msg_id)
            message["delivered"] = 1
            self.storage.save_message(message)
        else:
            logging.info("Relay message for %s from %s (id: %s)",
                         recipient, sender, msg_id)
            self.storage.save_relay_message(message)

    async def _sync_with_peer(self, peer: PeerInfo):
        if not self.network or peer.connection_type != "wifi":
            return

        local_profile = self.profile_mgr.get_local_profile()
        if not local_profile:
            return

        logging.info("Syncing with %s...", peer.fingerprint)

        try:
            my_profile = self.profile_mgr.export_profile_for_sharing()
            await self.network.transport.send_to_peer(peer, "profile", {
                "profile": my_profile
            })

            # Deliver messages targeted at this peer
            relay_messages = self.storage.get_relay_messages_for(peer.fingerprint)
            if relay_messages:
                for msg in relay_messages:
                    msg["encrypted_payload"] = json.loads(msg["encrypted_payload"]) \
                        if isinstance(msg["encrypted_payload"], str) else msg["encrypted_payload"]

                resp = await self.network.transport.send_to_peer(peer, "sync", {
                    "sender_fingerprint": local_profile["fingerprint"],
                    "messages_for_you": relay_messages,
                    "relay_messages": [],
                })

                if resp and resp.get("status") == "ok":
                    for msg in relay_messages:
                        self.storage.delete_relay_message(msg["message_id"])
                    logging.info("  %d messages delivered to %s",
                                 len(relay_messages), peer.fingerprint)

            # Sync broadcast messages (channels, files, SOS)
            broadcast_relay = []
            all_relay = self.storage.get_all_relay_messages()
            for msg in all_relay:
                msg["encrypted_payload"] = json.loads(msg["encrypted_payload"]) \
                    if isinstance(msg["encrypted_payload"], str) else msg["encrypted_payload"]
                payload = msg["encrypted_payload"]
                msg_type = payload.get("type", "") if isinstance(payload, dict) else ""
                if msg_type in ("channel", "channel_create", "file") or \
                   msg["recipient_fingerprint"] in ("__CHANNEL_BROADCAST__", "__PUBLIC__", "__SOS_BROADCAST__"):
                    broadcast_relay.append(msg)

            if broadcast_relay:
                resp = await self.network.transport.send_to_peer(peer, "sync", {
                    "sender_fingerprint": local_profile["fingerprint"],
                    "messages_for_you": broadcast_relay,
                    "relay_messages": [],
                })

            # Share relay inventory for store-and-forward
            relay_for_sync = []
            for msg in all_relay:
                if msg not in broadcast_relay:
                    relay_for_sync.append({
                        "message_id": msg["message_id"],
                        "recipient_fingerprint": msg["recipient_fingerprint"],
                        "sender_fingerprint": msg["sender_fingerprint"],
                    })

            resp = await self.network.transport.send_to_peer(peer, "sync", {
                "sender_fingerprint": local_profile["fingerprint"],
                "messages_for_you": [],
                "relay_inventory": relay_for_sync,
            })

            if resp:
                for msg in resp.get("messages_for_you", []):
                    await self._on_message_received(msg)
                for msg in resp.get("relay_messages", []):
                    self.storage.save_relay_message(msg)

            self.storage.log_peer(
                peer.fingerprint, peer.connection_type,
                peer.address, messages_exchanged=len(relay_messages)
            )

            logging.info("Sync with %s complete", peer.fingerprint)

        except Exception as e:
            logging.error("Sync error with %s: %s", peer.fingerprint, e)

    async def _handle_sync_request(self, request: dict) -> dict:
        local_profile = self.profile_mgr.get_local_profile()
        if not local_profile:
            return {"status": "error", "message": "Not initialized"}

        response = {"status": "ok", "messages_for_you": [], "relay_messages": []}

        for msg in request.get("messages_for_you", []):
            payload = msg.get("encrypted_payload", {})
            if isinstance(payload, dict):
                msg_type = payload.get("type", "")
                if msg_type in ("channel", "channel_create", "file"):
                    await self._on_message_received({"type": msg_type, **payload})
                    continue
            await self._on_message_received(msg)

        sender_fp = request.get("sender_fingerprint", "")
        if sender_fp:
            relay_for_peer = self.storage.get_relay_messages_for(sender_fp)
            for msg in relay_for_peer:
                msg["encrypted_payload"] = json.loads(msg["encrypted_payload"]) \
                    if isinstance(msg["encrypted_payload"], str) else msg["encrypted_payload"]
                response["messages_for_you"].append(msg)
                self.storage.delete_relay_message(msg["message_id"])

        return response

    def send_message(self, recipient_fingerprint: str, plaintext: str) -> dict:
        if not self.profile_mgr.crypto:
            raise RuntimeError("Profile not initialized")

        recipient = self.storage.get_profile(recipient_fingerprint)
        if not recipient:
            raise ValueError(f"Unknown recipient: {recipient_fingerprint}")

        encrypted = self.profile_mgr.crypto.encrypt_message(
            plaintext, recipient["box_public_key"]
        )

        message = {
            "message_id": str(uuid.uuid4()),
            "sender_fingerprint": self.profile_mgr.identity.fingerprint,
            "recipient_fingerprint": recipient_fingerprint,
            "encrypted_payload": encrypted,
            "timestamp": int(time.time()),
            "ttl": 604800,
            "hop_count": 0,
        }

        pow_data = f"{message['message_id']}{message['timestamp']}".encode()
        message["proof_of_work"] = CryptoEngine.generate_proof_of_work(pow_data, difficulty=16)

        self.storage.save_message(message)
        self.storage.save_relay_message(message)

        logging.info("Message sent to %s (id: %s)",
                     recipient_fingerprint, message["message_id"])

        return message

    def _save_received_file(self, file_msg: dict):
        """Save a file received from the mesh network to disk and DB."""
        file_data_b64 = file_msg.get("file_data_b64")
        if not file_data_b64:
            logging.warning("Received file message without data")
            return

        file_id = file_msg.get("file_id", str(uuid.uuid4()))
        files_dir = self.data_dir / "files"
        files_dir.mkdir(parents=True, exist_ok=True)

        encrypted_path = files_dir / f"{file_id}.enc"
        try:
            file_bytes = base64.b64decode(file_data_b64)
            encrypted_path.write_bytes(file_bytes)
            try:
                encrypted_path.chmod(0o600)
            except OSError:
                pass
        except Exception as e:
            logging.error("Failed to save received file: %s", e)
            return

        file_meta = {
            "file_id": file_id,
            "sender_fingerprint": file_msg.get("sender_fingerprint", ""),
            "recipient_fingerprint": file_msg.get("recipient_fingerprint", ""),
            "filename": file_msg.get("filename", "unknown"),
            "file_size": file_msg.get("file_size", len(file_bytes)),
            "mime_type": file_msg.get("mime_type", "application/octet-stream"),
            "encrypted_path": str(encrypted_path),
            "checksum": file_msg.get("checksum", ""),
            "timestamp": file_msg.get("timestamp", int(time.time())),
            "is_public": file_msg.get("is_public", 0),
            "description": file_msg.get("description", ""),
        }

        self.storage.save_shared_file(file_meta)
        logging.info("File '%s' saved (%s)", file_meta["filename"], file_id)

    def read_message(self, message_id: str) -> Optional[str]:
        if not self.profile_mgr.crypto:
            return None

        inbox = self.storage.get_inbox(self.profile_mgr.identity.fingerprint)
        for msg in inbox:
            if msg["message_id"] == message_id:
                payload = json.loads(msg["encrypted_payload"]) \
                    if isinstance(msg["encrypted_payload"], str) else msg["encrypted_payload"]
                plaintext = self.profile_mgr.crypto.decrypt_message(payload)
                if plaintext:
                    self.storage.mark_read(message_id)
                return plaintext

        return None

    async def _periodic_sync(self):
        while self._running:
            await asyncio.sleep(30)
            if self.network:
                for peer in self.network.get_peers():
                    if peer.connection_type == "wifi":
                        await self._sync_with_peer(peer)

    async def _periodic_cleanup(self):
        while self._running:
            await asyncio.sleep(3600)
            self.storage.cleanup_expired()
            logging.info("Expired messages cleanup done")


def run_daemon(data_dir: Path = None):
    """Entry point for the daemon."""
    data_dir = data_dir or DATA_DIR
    data_dir.mkdir(parents=True, exist_ok=True)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    daemon = MeshBoxDaemon(data_dir)

    if not daemon.is_initialized:
        print("ERROR: Profile not initialized.")
        print("Run first: meshbox profile create --name 'Your Name'")
        sys.exit(1)

    asyncio.run(daemon.start())
