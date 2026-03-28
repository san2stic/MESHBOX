"""
MeshBox - Encrypted file sharing.
E2E encrypted file sharing over the mesh network.
Same system as messages: E2E encryption + store-and-forward.
"""

import hashlib
import json
import mimetypes
import os
import time
import uuid
from pathlib import Path
from typing import Optional

from meshbox.crypto import CryptoEngine, Identity
from meshbox.storage import StorageEngine


class FileManager:
    """Encrypted file sharing management over the mesh network."""

    def __init__(self, storage: StorageEngine, identity: Identity,
                 files_dir: Path):
        self.storage = storage
        self.identity = identity
        self.crypto = CryptoEngine(identity)
        self.files_dir = files_dir
        self.files_dir.mkdir(parents=True, exist_ok=True)

    def share_file(self, file_data: bytes, filename: str,
                   recipient_fingerprint: str = "",
                   description: str = "",
                   is_public: bool = False,
                   max_file_size: int = 10 * 1024 * 1024) -> dict:
        """
        Share an encrypted file.
        - If recipient_fingerprint is provided: E2E encryption for that recipient
        - If is_public: file accessible to all nodes
        """
        if len(file_data) > max_file_size:
            raise ValueError(f"File too large (max {max_file_size // (1024*1024)} MB)")

        file_id = str(uuid.uuid4())
        checksum = hashlib.sha256(file_data).hexdigest()
        mime_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"

        encrypted_filename = f"{file_id}.enc"
        encrypted_path = self.files_dir / encrypted_filename

        if recipient_fingerprint and not is_public:
            contact = self.storage.get_profile(recipient_fingerprint)
            if not contact:
                raise ValueError("Unknown recipient")
            encrypted = self.crypto.encrypt_message(
                file_data.hex(), contact["box_public_key"]
            )
            encrypted_path.write_text(json.dumps(encrypted))
        else:
            encrypted_path.write_bytes(file_data)

        try:
            encrypted_path.chmod(0o600)
        except OSError:
            pass

        file_meta = {
            "file_id": file_id,
            "sender_fingerprint": self.identity.fingerprint,
            "recipient_fingerprint": recipient_fingerprint,
            "filename": filename,
            "file_size": len(file_data),
            "mime_type": mime_type,
            "encrypted_path": str(encrypted_path),
            "checksum": checksum,
            "timestamp": int(time.time()),
            "is_public": 1 if is_public else 0,
            "description": description,
        }

        self.storage.save_shared_file(file_meta)
        return file_meta

    def get_file_data(self, file_id: str) -> Optional[tuple]:
        """
        Retrieve and decrypt a file.
        Returns (filename, mime_type, data_bytes) or None.
        """
        file_meta = self.storage.get_file_by_id(file_id)
        if not file_meta:
            return None

        encrypted_path = Path(file_meta["encrypted_path"])
        if not encrypted_path.exists():
            return None

        if file_meta["recipient_fingerprint"] and not file_meta.get("is_public"):
            encrypted = json.loads(encrypted_path.read_text())
            hex_data = self.crypto.decrypt_message(encrypted)
            if hex_data is None:
                return None
            file_data = bytes.fromhex(hex_data)
        else:
            file_data = encrypted_path.read_bytes()

        return (file_meta["filename"], file_meta["mime_type"], file_data)

    def delete_file(self, file_id: str):
        file_meta = self.storage.get_file_by_id(file_id)
        if file_meta:
            path = Path(file_meta["encrypted_path"])
            if path.exists():
                path.unlink()
            self.storage.delete_shared_file(file_id)

    def get_my_files(self) -> list:
        return self.storage.get_my_files(self.identity.fingerprint)

    def get_received_files(self) -> list:
        return self.storage.get_files_for_me(self.identity.fingerprint)

    def get_public_files(self) -> list:
        return self.storage.get_public_files()

    @staticmethod
    def format_file_size(size_bytes: int) -> str:
        if size_bytes < 1024:
            return f"{size_bytes} B"
        if size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        return f"{size_bytes / (1024 * 1024):.1f} MB"

    @staticmethod
    def get_file_icon(mime_type: str) -> str:
        if not mime_type:
            return "📄"
        if mime_type.startswith("image/"):
            return "🖼"
        if mime_type.startswith("audio/"):
            return "🎵"
        if mime_type.startswith("video/"):
            return "🎬"
        if mime_type.startswith("text/"):
            return "📝"
        if "pdf" in mime_type:
            return "📑"
        if "zip" in mime_type or "tar" in mime_type or "compress" in mime_type:
            return "📦"
        return "📄"
