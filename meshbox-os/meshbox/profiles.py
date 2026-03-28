"""
MeshBox - User profile management.
Each user has a unique cryptographic identity.
"""

import time
from pathlib import Path
from typing import Optional

from meshbox.crypto import Identity, CryptoEngine
from meshbox.storage import StorageEngine


class ProfileManager:
    """MeshBox user profile management."""

    def __init__(self, storage: StorageEngine, keys_dir: Path):
        self.storage = storage
        self.keys_dir = keys_dir
        self.identity: Optional[Identity] = None
        self.crypto: Optional[CryptoEngine] = None
        self._load_identity()

    def _load_identity(self):
        """Load local identity if it exists."""
        self.identity = Identity.load(self.keys_dir)
        if self.identity:
            self.crypto = CryptoEngine(self.identity)

    @property
    def is_initialized(self) -> bool:
        """Check if a local profile exists."""
        return self.identity is not None

    def create_profile(self, name: str, bio: str = "") -> dict:
        """Create a new local profile with a cryptographic identity."""
        if self.is_initialized:
            raise RuntimeError("A local profile already exists. Delete it first.")

        self.identity = Identity.generate()
        self.identity.save(self.keys_dir)
        self.crypto = CryptoEngine(self.identity)

        public_keys = self.identity.export_public()
        profile = {
            "fingerprint": public_keys["fingerprint"],
            "name": name,
            "verify_key": public_keys["verify_key"],
            "box_public_key": public_keys["box_public_key"],
            "bio": bio,
            "created_at": int(time.time()),
            "is_local": 1,
        }

        self.storage.save_profile(profile)
        return profile

    def get_local_profile(self) -> Optional[dict]:
        return self.storage.get_local_profile()

    def update_profile(self, name: str = None, bio: str = None):
        """Update the local profile."""
        profile = self.get_local_profile()
        if not profile:
            raise RuntimeError("No local profile found.")

        if name:
            profile["name"] = name
        if bio is not None:
            profile["bio"] = bio

        self.storage.save_profile(profile)

    def get_contact(self, fingerprint: str) -> Optional[dict]:
        return self.storage.get_profile(fingerprint)

    def get_all_contacts(self) -> list:
        return [p for p in self.storage.get_all_profiles() if not p.get("is_local")]

    def add_contact_from_discovery(self, peer_data: dict) -> dict:
        """Add a contact discovered on the network."""
        profile = {
            "fingerprint": peer_data["fingerprint"],
            "name": peer_data.get("name", "Unknown"),
            "verify_key": peer_data["verify_key"],
            "box_public_key": peer_data["box_public_key"],
            "bio": peer_data.get("bio", ""),
            "created_at": peer_data.get("created_at", int(time.time())),
            "is_local": 0,
        }
        self.storage.save_profile(profile)
        return profile

    def export_profile_for_sharing(self) -> dict:
        """Export the local profile for sharing (network discovery)."""
        profile = self.get_local_profile()
        if not profile:
            raise RuntimeError("No local profile.")

        return {
            "fingerprint": profile["fingerprint"],
            "name": profile["name"],
            "verify_key": profile["verify_key"],
            "box_public_key": profile["box_public_key"],
            "bio": profile.get("bio", ""),
            "created_at": profile["created_at"],
        }
