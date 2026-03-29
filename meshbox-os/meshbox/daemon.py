"""
MeshBox Daemon v4 (meshboxd)
Main daemon that coordinates all components:
- Network discovery (WiFi + Bluetooth + Tor)
- Profile and message exchange
- Store-and-forward protocol with epidemic routing
- Onion routing for sender anonymity
- Message deduplication and hop limiting
- Delivery receipts and acknowledgments
- Periodic cleanup (TTL, disappearing messages)
- Tor hidden service for internet-based P2P
- Peer gossip for relay optimization
- Adaptive sync intervals
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

from meshbox.config import DATA_DIR, TOR_ENABLED_DEFAULT, GOSSIP_INTERVAL, NETWORK_STATS_SAVE_INTERVAL
from meshbox.crypto import Identity, CryptoEngine
from meshbox.files import FileManager
from meshbox.network import (
    NetworkManager, PeerInfo, MessageTransport, OnionLayer, MAX_HOP_COUNT,
)
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
        self.tor_manager = None
        self.directory_client = None
        self._running = False
        self._sync_interval = 30  # adaptive: starts at 30s, adjusts based on activity
        self._last_activity = time.time()

    @property
    def is_initialized(self) -> bool:
        return self.profile_mgr.is_initialized

    async def start(self):
        """Start the MeshBox daemon."""
        if not self.is_initialized:
            logging.error("Profile not initialized. Run 'meshbox profile create' first.")
            return

        profile = self.profile_mgr.export_profile_for_sharing()
        logging.info("Starting MeshBox daemon v4 - %s (%s)",
                     profile["name"], profile["fingerprint"])

        # Wire storage-backed nonce tracker into crypto engine
        if self.profile_mgr.crypto:
            self.profile_mgr.crypto.nonce_tracker._storage = self.storage

        self.file_mgr = FileManager(
            self.storage, self.profile_mgr.identity,
            self.data_dir / "files"
        )

        self.network = NetworkManager(profile, signing_key=self.profile_mgr.identity.signing_key)
        self.network.on_peer_discovered = self._on_peer_discovered
        self.network.on_message_received = self._on_message_received
        self.network.on_delivery_receipt = self._on_delivery_receipt
        self.network.transport.on_sync_request = self._handle_sync_request

        self._running = True

        tasks = [
            asyncio.create_task(self.network.start()),
            asyncio.create_task(self._periodic_sync()),
            asyncio.create_task(self._periodic_cleanup()),
            asyncio.create_task(self._periodic_gossip()),
            asyncio.create_task(self._periodic_stats()),
        ]

        # Start Tor if enabled
        tor_enabled = self.storage.get_setting("tor_enabled", str(TOR_ENABLED_DEFAULT).lower())
        if tor_enabled == "true":
            tasks.append(asyncio.create_task(self._start_tor()))

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
        if self.tor_manager:
            try:
                self.tor_manager.stop()
            except Exception:
                pass
        self.storage.close()

    async def _start_tor(self):
        """Initialize Tor hidden service and directory client."""
        try:
            from meshbox.tor import TorManager
            from meshbox.directory import DirectoryClient

            self.tor_manager = TorManager(self.data_dir)
            started = await self.tor_manager.start()
            if not started:
                logging.warning("Tor failed to start - internet P2P disabled")
                return

            onion = self.tor_manager.onion_address
            logging.info("Tor hidden service: %s", onion)

            # Register with network manager
            if self.network:
                self.network.set_tor_transport(self.tor_manager)

            # Start directory client for peer discovery
            profile = self.profile_mgr.export_profile_for_sharing()
            self.directory_client = DirectoryClient(
                self.storage, self.tor_manager, profile
            )

            # Check if directory node mode is enabled
            dir_enabled = self.storage.get_setting("directory_node_enabled", "false") == "true"
            if dir_enabled:
                self.directory_client.set_directory_mode(True)
                logging.info("Directory node mode is ACTIVE - serving as directory node")

            # Wire directory handlers into network transport
            if self.network:
                self.network.transport.on_directory_announce = self.directory_client.handle_announce
                self.network.transport.on_directory_query = self.directory_client.handle_query
                self.network.transport.on_peer_gossip = self.directory_client.handle_gossip

            await self.directory_client.start()

        except ImportError:
            logging.info("Tor modules not available (install stem + PySocks)")
        except Exception as e:
            logging.error("Tor initialization failed: %s", e)

    async def _on_delivery_receipt(self, receipt: dict):
        """Handle incoming delivery receipts."""
        msg_id = receipt.get("message_id", "")
        sender = receipt.get("sender_fingerprint", "")
        receipt_type = receipt.get("type", "receipt")

        if receipt_type == "receipt_ack":
            logging.debug("Receipt ACK for %s from %s", msg_id, sender)
            return

        if msg_id:
            self.storage.save_delivery_receipt(msg_id, sender)
            self.storage.update_delivery_status(msg_id, "delivered")
            logging.info("Delivery receipt: %s confirmed by %s", msg_id, sender)
            self._last_activity = time.time()

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

        # Handle onion-routed messages
        if msg_type == "onion" or message.get("onion"):
            await self._handle_onion_message(message)
            return

        # Deduplicate: check if we've already seen this message
        msg_id = message.get("message_id", "")
        if msg_id and self.storage.is_message_seen(msg_id):
            logging.debug("Duplicate message ignored: %s", msg_id)
            return
        if msg_id:
            self.storage.mark_message_seen(msg_id)

        # Check hop count
        hop_count = message.get("hop_count", 0)
        if hop_count > MAX_HOP_COUNT:
            logging.warning("Message %s exceeded max hops (%d), dropping", msg_id, hop_count)
            return

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
            message["delivery_status"] = "delivered"
            self.storage.save_message(message)
            # Update trust for the sender
            self.storage.update_trust_score(sender, True)
            self._last_activity = time.time()

            # Send delivery receipt back
            if self.network and sender:
                asyncio.create_task(self._send_delivery_receipt(sender, msg_id))
        else:
            logging.info("Relay message for %s from %s (id: %s)",
                         recipient, sender, msg_id)
            # Increment hop count before relaying
            message["hop_count"] = hop_count + 1
            self.storage.save_relay_message(message)

    async def _handle_onion_message(self, message: dict):
        """Handle an onion-routed message: unwrap our layer and process/forward."""
        if not self.profile_mgr.identity:
            return

        inner = OnionLayer.unwrap_onion(message, self.profile_mgr.identity.box_key)
        if inner is None:
            logging.warning("Failed to unwrap onion layer")
            return

        # Check if the inner payload is another onion layer
        if inner.get("onion"):
            next_hop = inner.get("next_hop", "")
            if self.network and next_hop:
                result = await self.network.send_to_peer_or_tor(next_hop, "onion", inner, storage=self.storage)
                if result:
                    logging.info("Forwarding onion message to %s", next_hop)
                else:
                    # Store for later relay when the peer comes online
                    relay_msg = {
                        "message_id": f"onion-{uuid.uuid4()}",
                        "sender_fingerprint": "__ONION__",
                        "recipient_fingerprint": next_hop,
                        "encrypted_payload": inner,
                        "timestamp": int(time.time()),
                        "ttl": 86400,
                        "hop_count": 0,
                    }
                    self.storage.save_relay_message(relay_msg)
        else:
            # Final destination: process the inner message
            await self._on_message_received(inner)

    async def _send_delivery_receipt(self, recipient_fp: str, message_id: str):
        """Send a delivery receipt to the sender."""
        try:
            receipt_payload = {
                "message_id": message_id,
                "sender_fingerprint": self.profile_mgr.identity.fingerprint,
                "timestamp": int(time.time()),
            }
            await self.network.send_to_peer_or_tor(
                recipient_fp, "receipt", receipt_payload, storage=self.storage
            )
        except Exception as e:
            logging.debug("Failed to send delivery receipt: %s", e)

    async def _sync_with_peer(self, peer: PeerInfo):
        if not self.network or peer.connection_type not in ("wifi", "mdns"):
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
                    self.storage.update_trust_score(peer.fingerprint, True)

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
            self.storage.update_trust_score(peer.fingerprint, False)

    async def _handle_sync_request(self, request: dict) -> dict:
        local_profile = self.profile_mgr.get_local_profile()
        if not local_profile:
            return {"status": "error", "message": "Not initialized"}

        response = {"status": "ok", "messages_for_you": [], "relay_messages": []}

        for msg in request.get("messages_for_you", []):
            # Deduplicate incoming sync messages
            msg_id = msg.get("message_id", "")
            if msg_id and self.storage.is_message_seen(msg_id):
                continue

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

    def send_message(self, recipient_fingerprint: str, plaintext: str,
                     disappear_after_read: bool = False,
                     disappear_timer: int = 0,
                     use_onion: bool = False) -> dict:
        """Send an encrypted message with optional disappearing and onion routing."""
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
            "disappear_after_read": 1 if disappear_after_read else 0,
            "disappear_timer": disappear_timer,
        }

        pow_data = f"{message['message_id']}{message['timestamp']}".encode()
        message["proof_of_work"] = CryptoEngine.generate_proof_of_work(pow_data, difficulty=16)

        self.storage.save_message(message)

        # Optionally wrap in onion layers for sender anonymity
        relay_payload = message.copy()
        if use_onion and self.network:
            trusted_peers = self.network.get_trusted_peers(min_trust=0.4)
            if len(trusted_peers) >= 2:
                # Pick up to 3 intermediate hops
                import random
                route = random.sample(trusted_peers[:10], min(3, len(trusted_peers)))
                relay_payload = OnionLayer.wrap_onion(
                    message, route, self.profile_mgr.identity.box_key
                )
                logging.info("Message wrapped in %d onion layers", len(route))

        self.storage.save_relay_message(relay_payload if not relay_payload.get("onion") else message)

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
            await asyncio.sleep(self._sync_interval)

            # Adaptive sync: sync more frequently when active
            idle_time = time.time() - self._last_activity
            if idle_time < 60:
                self._sync_interval = 15  # very active
            elif idle_time < 300:
                self._sync_interval = 30  # moderately active
            else:
                self._sync_interval = 120  # idle

            if self.network:
                peers = self.network.get_peers()
                # Sync with all LAN peers (wifi + mdns)
                for peer in peers:
                    if peer.connection_type in ("wifi", "mdns"):
                        await self._sync_with_peer(peer)

                # Also sync with Tor peers
                if self.tor_manager and self.directory_client:
                    tor_peers = self.storage.get_active_tor_peers()
                    for tp in tor_peers[:10]:  # limit to 10 most active
                        await self._sync_with_tor_peer(tp)

    async def _sync_with_tor_peer(self, tor_peer: dict):
        """Sync relay messages with a Tor peer."""
        if not self.tor_manager or not self.network:
            return
        try:
            fp = tor_peer["fingerprint"]
            onion = tor_peer.get("onion_address", "")
            if not onion:
                return
            relay_messages = self.storage.get_relay_messages_for(fp)
            if relay_messages:
                for msg in relay_messages:
                    msg["encrypted_payload"] = json.loads(msg["encrypted_payload"]) \
                        if isinstance(msg["encrypted_payload"], str) else msg["encrypted_payload"]
                resp = await self.tor_manager.send_to_onion(
                    onion, "sync", {
                        "sender_fingerprint": self.profile_mgr.identity.fingerprint,
                        "messages_for_you": relay_messages,
                        "relay_messages": [],
                    },
                    storage=self.storage,
                )
                if resp and resp.get("status") == "ok":
                    for msg in relay_messages:
                        self.storage.delete_relay_message(msg["message_id"])
                    logging.info("Tor sync: %d messages to %s", len(relay_messages), fp[:8])
        except Exception as e:
            logging.debug("Tor sync error with %s: %s", tor_peer.get("fingerprint", "?")[:8], e)

    async def _periodic_gossip(self):
        """Periodically gossip peer lists with neighbors for relay optimization."""
        await asyncio.sleep(30)  # Initial delay
        while self._running:
            try:
                if self.network and self.directory_client:
                    # Gossip with local WiFi/mDNS peers
                    tor_peers = self.storage.get_active_tor_peers(max_age=3600)
                    for tp in tor_peers[:5]:
                        onion = tp.get("onion_address", "")
                        if onion:
                            await self.directory_client.gossip_peers(onion)

                    # Gossip with directly connected peers via TCP
                    local_peers = self.network.get_peers()
                    if local_peers:
                        my_fp = self.profile_mgr.identity.fingerprint
                        known_peers = self.storage.get_active_tor_peers(max_age=7200)
                        peer_list = [
                            {
                                "fingerprint": p.get("fingerprint", ""),
                                "onion_address": p.get("onion_address", ""),
                                "name": p.get("name", ""),
                            }
                            for p in known_peers[:20]
                        ]
                        for peer in local_peers[:5]:
                            if peer.connection_type in ("wifi", "mdns"):
                                await self.network.transport.send_to_peer(
                                    peer, "peer_gossip", {
                                        "fingerprint": my_fp,
                                        "peers": peer_list,
                                    },
                                    retries=1,
                                )
            except Exception as e:
                logging.debug("Gossip error: %s", e)

            await asyncio.sleep(GOSSIP_INTERVAL)

    async def _periodic_stats(self):
        """Periodically persist network statistics."""
        while self._running:
            await asyncio.sleep(NETWORK_STATS_SAVE_INTERVAL)
            try:
                if self.network:
                    bw = self.network.transport.get_bandwidth_stats()
                    self.storage.set_setting("net_bytes_sent",
                                             str(bw.get("bytes_sent", 0)))
                    self.storage.set_setting("net_bytes_received",
                                             str(bw.get("bytes_received", 0)))
                    self.storage.set_setting("net_messages_sent",
                                             str(bw.get("messages_sent", 0)))
                    self.storage.set_setting("net_messages_received",
                                             str(bw.get("messages_received", 0)))
                    self.storage.set_setting("net_active_peers",
                                             str(len(self.network.get_peers())))
            except Exception as e:
                logging.debug("Stats persistence error: %s", e)

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
