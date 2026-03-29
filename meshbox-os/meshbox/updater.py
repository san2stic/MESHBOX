"""
MeshBox - Update checker v4.
Check for updates via Tor or direct HTTPS.
- Fetches latest version info from a signed manifest
- Verifies update signatures using trusted public keys
- Non-blocking async checks
"""

import asyncio
import hashlib
import json
import logging
import time
from typing import Optional

import meshbox
from meshbox.config import UPDATE_CHECK_INTERVAL, UPDATE_TRUSTED_KEYS

logger = logging.getLogger("meshbox.updater")


class UpdateChecker:
    """Check for MeshBox updates."""

    # Update manifest URL (can be .onion or clearnet)
    UPDATE_MANIFEST_URLS = [
        # Add official update URLs here when available
    ]

    def __init__(self, storage=None, tor_manager=None):
        self.storage = storage
        self.tor = tor_manager
        self._last_check = 0
        self._latest_version: Optional[str] = None
        self._update_info: Optional[dict] = None

    @property
    def current_version(self) -> str:
        return meshbox.__version__

    @property
    def update_available(self) -> bool:
        if not self._latest_version:
            return False
        return self._compare_versions(self._latest_version, self.current_version) > 0

    async def check_for_updates(self, force: bool = False) -> Optional[dict]:
        """
        Check for available updates.
        Returns update info dict or None if no update available.
        """
        now = time.time()
        if not force and (now - self._last_check) < UPDATE_CHECK_INTERVAL:
            return self._update_info if self.update_available else None

        self._last_check = now

        for url in self.UPDATE_MANIFEST_URLS:
            try:
                manifest = await self._fetch_manifest(url)
                if manifest and self._verify_manifest(manifest):
                    self._latest_version = manifest.get("version")
                    self._update_info = manifest

                    if self.storage:
                        self.storage.set_setting("last_update_check", str(int(now)))
                        self.storage.set_setting("latest_version", self._latest_version or "")

                    if self.update_available:
                        logger.info("Update available: %s -> %s",
                                   self.current_version, self._latest_version)
                        return manifest
                    else:
                        logger.debug("No update available (current: %s, latest: %s)",
                                    self.current_version, self._latest_version)
                        return None
            except Exception as e:
                logger.debug("Update check from %s failed: %s", url[:30], e)
                continue

        return None

    async def _fetch_manifest(self, url: str) -> Optional[dict]:
        """Fetch update manifest from URL."""
        try:
            import aiohttp

            if url.endswith(".onion") or ".onion/" in url:
                # Use Tor SOCKS proxy
                connector = None
                try:
                    import aiohttp_socks
                    from meshbox.config import TOR_SOCKS_PORT
                    connector = aiohttp_socks.ProxyConnector.from_url(
                        f"socks5://127.0.0.1:{TOR_SOCKS_PORT}"
                    )
                except ImportError:
                    logger.debug("aiohttp_socks not available for .onion URLs")
                    return None

                async with aiohttp.ClientSession(connector=connector) as session:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                        if resp.status == 200:
                            return await resp.json()
            else:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                        if resp.status == 200:
                            return await resp.json()
        except ImportError:
            logger.debug("aiohttp not available for update checks")
        except Exception as e:
            logger.debug("Manifest fetch error: %s", e)

        return None

    def _verify_manifest(self, manifest: dict) -> bool:
        """Verify the update manifest signature."""
        if not UPDATE_TRUSTED_KEYS:
            # No trusted keys configured - accept unsigned manifests
            # (for development; production should require signatures)
            return True

        signature = manifest.get("signature", "")
        if not signature:
            logger.warning("Update manifest has no signature")
            return False

        # Verify the signature against trusted keys
        try:
            import nacl.signing
            import nacl.encoding

            manifest_copy = {k: v for k, v in manifest.items() if k != "signature"}
            manifest_bytes = json.dumps(manifest_copy, sort_keys=True).encode()

            for trusted_key_b64 in UPDATE_TRUSTED_KEYS:
                try:
                    vk = nacl.signing.VerifyKey(
                        trusted_key_b64.encode(), nacl.encoding.Base64Encoder
                    )
                    sig_bytes = nacl.encoding.Base64Encoder.decode(signature.encode())
                    vk.verify(manifest_bytes, sig_bytes)
                    return True
                except Exception:
                    continue

            logger.warning("No trusted key matched the manifest signature")
            return False
        except ImportError:
            logger.warning("nacl not available for signature verification")
            return False

    @staticmethod
    def _compare_versions(v1: str, v2: str) -> int:
        """Compare version strings. Returns >0 if v1 > v2, 0 if equal, <0 if v1 < v2."""
        def parse(v):
            parts = []
            for p in v.split("."):
                try:
                    parts.append(int(p))
                except ValueError:
                    parts.append(0)
            return parts

        p1, p2 = parse(v1), parse(v2)
        # Pad shorter list
        while len(p1) < len(p2):
            p1.append(0)
        while len(p2) < len(p1):
            p2.append(0)

        for a, b in zip(p1, p2):
            if a > b:
                return 1
            if a < b:
                return -1
        return 0

    def get_status(self) -> dict:
        """Get update checker status."""
        return {
            "current_version": self.current_version,
            "latest_version": self._latest_version,
            "update_available": self.update_available,
            "last_check": self._last_check,
            "update_info": self._update_info,
        }
