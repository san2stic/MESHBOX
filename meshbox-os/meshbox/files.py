"""
MeshBox - Encrypted file sharing v4.
E2E encrypted file sharing over the mesh network.
- Base64 encoding for encrypted payloads (not hex)
- File chunking for large files (up to 50 MB)
- SHA-256 integrity verification
- Same system as messages: E2E encryption + store-and-forward
"""

import base64
import hashlib
import json
import mimetypes
import os
import time
import uuid
from pathlib import Path
from typing import Optional

from meshbox.config import MAX_FILE_SIZE, FILE_CHUNK_SIZE
from meshbox.crypto import CryptoEngine, Identity
from meshbox.storage import StorageEngine


class FileManager:
    """Encrypted file sharing management over the mesh network."""

    def __init__(self, storage: StorageEngine, identity: Identity,
                 files_dir: Path):
        self.storage = storage
        self.identity = identity
        self.crypto = CryptoEngine(identity, storage=storage)
        self.files_dir = files_dir
        self.files_dir.mkdir(parents=True, exist_ok=True)

    def share_file(self, file_data: bytes, filename: str,
                   recipient_fingerprint: str = "",
                   description: str = "",
                   is_public: bool = False) -> dict:
        """
        Share an encrypted file.
        - If recipient_fingerprint is provided: E2E encryption for that recipient
        - If is_public: file accessible to all nodes
        - Large files are chunked at FILE_CHUNK_SIZE boundaries
        """
        if len(file_data) > MAX_FILE_SIZE:
            raise ValueError(f"File too large (max {MAX_FILE_SIZE // (1024*1024)} MB)")

        file_id = str(uuid.uuid4())
        checksum = hashlib.sha256(file_data).hexdigest()
        mime_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"

        encrypted_filename = f"{file_id}.enc"
        encrypted_path = self.files_dir / encrypted_filename

        if recipient_fingerprint and not is_public:
            contact = self.storage.get_profile(recipient_fingerprint)
            if not contact:
                raise ValueError("Unknown recipient")
            # Use base64 encoding instead of hex for efficiency
            encoded_data = base64.b64encode(file_data).decode("ascii")
            encrypted = self.crypto.encrypt_message(
                encoded_data, contact["box_public_key"]
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

    def prepare_file_for_transfer(self, file_id: str) -> list:
        """
        Prepare file for mesh transfer by chunking.
        Returns list of chunk dicts ready for relay.
        """
        file_meta = self.storage.get_file_by_id(file_id)
        if not file_meta:
            return []

        encrypted_path = Path(file_meta["encrypted_path"])
        if not encrypted_path.exists():
            return []

        raw = encrypted_path.read_bytes()
        chunks = []
        total_chunks = (len(raw) + FILE_CHUNK_SIZE - 1) // FILE_CHUNK_SIZE

        for i in range(total_chunks):
            start = i * FILE_CHUNK_SIZE
            end = min(start + FILE_CHUNK_SIZE, len(raw))
            chunk_data = raw[start:end]
            chunk_hash = hashlib.sha256(chunk_data).hexdigest()

            chunks.append({
                "file_id": file_id,
                "chunk_index": i,
                "total_chunks": total_chunks,
                "chunk_data_b64": base64.b64encode(chunk_data).decode("ascii"),
                "chunk_hash": chunk_hash,
                "filename": file_meta["filename"],
                "file_size": file_meta["file_size"],
                "mime_type": file_meta["mime_type"],
                "checksum": file_meta["checksum"],
                "sender_fingerprint": file_meta["sender_fingerprint"],
                "recipient_fingerprint": file_meta.get("recipient_fingerprint", ""),
                "is_public": file_meta.get("is_public", 0),
                "description": file_meta.get("description", ""),
                "timestamp": file_meta["timestamp"],
            })

        return chunks

    def reassemble_chunks(self, chunks: list) -> Optional[dict]:
        """
        Reassemble file chunks into a complete file.
        Verifies integrity of each chunk and the final file.
        Returns file_meta dict or None on failure.
        """
        if not chunks:
            return None

        # Sort by chunk index
        chunks.sort(key=lambda c: c["chunk_index"])
        total = chunks[0].get("total_chunks", 1)
        if len(chunks) != total:
            return None

        # Verify and reassemble
        raw = bytearray()
        for chunk in chunks:
            chunk_data = base64.b64decode(chunk["chunk_data_b64"])
            chunk_hash = hashlib.sha256(chunk_data).hexdigest()
            if chunk_hash != chunk.get("chunk_hash", ""):
                return None  # Integrity failure
            raw.extend(chunk_data)

        # Verify overall checksum
        overall_hash = hashlib.sha256(bytes(raw)).hexdigest()
        expected = chunks[0].get("checksum", "")
        if expected and overall_hash != expected:
            return None

        file_id = chunks[0].get("file_id", str(uuid.uuid4()))
        encrypted_path = self.files_dir / f"{file_id}.enc"
        encrypted_path.write_bytes(bytes(raw))
        try:
            encrypted_path.chmod(0o600)
        except OSError:
            pass

        file_meta = {
            "file_id": file_id,
            "sender_fingerprint": chunks[0].get("sender_fingerprint", ""),
            "recipient_fingerprint": chunks[0].get("recipient_fingerprint", ""),
            "filename": chunks[0].get("filename", "unknown"),
            "file_size": chunks[0].get("file_size", len(raw)),
            "mime_type": chunks[0].get("mime_type", "application/octet-stream"),
            "encrypted_path": str(encrypted_path),
            "checksum": overall_hash,
            "timestamp": chunks[0].get("timestamp", int(time.time())),
            "is_public": chunks[0].get("is_public", 0),
            "description": chunks[0].get("description", ""),
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
            b64_data = self.crypto.decrypt_message(encrypted)
            if b64_data is None:
                return None
            try:
                file_data = base64.b64decode(b64_data)
            except Exception:
                # Fallback for v3 hex-encoded files
                try:
                    file_data = bytes.fromhex(b64_data)
                except ValueError:
                    return None
        else:
            file_data = encrypted_path.read_bytes()

        # Verify integrity
        if file_meta.get("checksum"):
            actual_hash = hashlib.sha256(file_data).hexdigest()
            if actual_hash != file_meta["checksum"]:
                return None

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
