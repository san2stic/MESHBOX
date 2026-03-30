"""Tests for meshbox.crypto.node_identity."""

import json
import tempfile
from pathlib import Path

import pytest

from meshbox.crypto.node_identity import NodeIdentity


class TestNodeIdentityGeneration:
    def test_generate_creates_identity(self):
        identity = NodeIdentity.generate()
        assert identity.signing_key is not None
        assert identity.verify_key is not None
        assert identity.box_private is not None
        assert identity.box_public is not None
        assert len(identity.node_id) == 64  # SHA3-256 hex

    def test_node_id_is_deterministic_for_same_key(self):
        identity = NodeIdentity.generate()
        assert identity.node_id == identity._compute_node_id()

    def test_two_identities_differ(self):
        id1 = NodeIdentity.generate()
        id2 = NodeIdentity.generate()
        assert id1.node_id != id2.node_id


class TestNodeIdentitySignature:
    def test_sign_and_verify(self):
        identity = NodeIdentity.generate()
        data = b"Hello, MeshBox!"
        sig = identity.sign_message(data)
        assert len(sig) == 64

        pubkey = identity.verify_key.encode()
        assert NodeIdentity.verify_message(data, sig, pubkey) is True

    def test_verify_rejects_bad_signature(self):
        identity = NodeIdentity.generate()
        data = b"Hello"
        sig = identity.sign_message(data)
        bad_sig = bytes(64)
        assert NodeIdentity.verify_message(data, bad_sig, identity.verify_key.encode()) is False

    def test_verify_rejects_tampered_data(self):
        identity = NodeIdentity.generate()
        data = b"Hello"
        sig = identity.sign_message(data)
        assert NodeIdentity.verify_message(b"Tampered", sig, identity.verify_key.encode()) is False

    def test_verify_rejects_wrong_key(self):
        id1 = NodeIdentity.generate()
        id2 = NodeIdentity.generate()
        data = b"test"
        sig = id1.sign_message(data)
        assert NodeIdentity.verify_message(data, sig, id2.verify_key.encode()) is False


class TestNodeIdentityEncryption:
    def test_encrypt_decrypt_roundtrip(self):
        sender = NodeIdentity.generate()
        receiver = NodeIdentity.generate()

        plaintext = b"Secret message for the mesh"
        encrypted = sender.encrypt_for_peer(
            plaintext, receiver.box_public.encode()
        )

        assert "ciphertext" in encrypted
        assert "nonce" in encrypted
        assert "ephemeral_pubkey" in encrypted

        decrypted = receiver.decrypt_from_peer(encrypted)
        assert decrypted == plaintext

    def test_encryption_uses_ephemeral_keys(self):
        sender = NodeIdentity.generate()
        receiver = NodeIdentity.generate()

        enc1 = sender.encrypt_for_peer(b"msg1", receiver.box_public.encode())
        enc2 = sender.encrypt_for_peer(b"msg2", receiver.box_public.encode())

        # Ephemeral keys should differ (PFS)
        assert enc1["ephemeral_pubkey"] != enc2["ephemeral_pubkey"]

    def test_wrong_receiver_cannot_decrypt(self):
        sender = NodeIdentity.generate()
        receiver = NodeIdentity.generate()
        wrong = NodeIdentity.generate()

        encrypted = sender.encrypt_for_peer(b"secret", receiver.box_public.encode())
        with pytest.raises(Exception):
            wrong.decrypt_from_peer(encrypted)


class TestNodeIdentityPersistence:
    def test_save_and_load_plaintext(self, tmp_path):
        identity = NodeIdentity.generate()
        identity.save(tmp_path)

        loaded = NodeIdentity.load(tmp_path)
        assert loaded.node_id == identity.node_id
        assert loaded.verify_key.encode() == identity.verify_key.encode()
        assert loaded.box_public.encode() == identity.box_public.encode()

    def test_save_and_load_encrypted(self, tmp_path):
        identity = NodeIdentity.generate()
        passphrase = "test-pass-123"
        identity.save(tmp_path, passphrase=passphrase)

        loaded = NodeIdentity.load(tmp_path, passphrase=passphrase)
        assert loaded.node_id == identity.node_id

    def test_wrong_passphrase_fails(self, tmp_path):
        identity = NodeIdentity.generate()
        identity.save(tmp_path, passphrase="correct")

        with pytest.raises(Exception):
            NodeIdentity.load(tmp_path, passphrase="wrong")

    def test_file_permissions(self, tmp_path):
        import os
        identity = NodeIdentity.generate()
        path = identity.save(tmp_path)
        perms = os.stat(path).st_mode & 0o777
        assert perms == 0o600

    def test_load_nonexistent_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            NodeIdentity.load(tmp_path / "nonexistent")


class TestNodeIdentityExport:
    def test_export_public(self):
        identity = NodeIdentity.generate()
        pub = identity.export_public()
        assert pub["node_id"] == identity.node_id
        assert "pubkey_ed25519" in pub
        assert "pubkey_x25519" in pub
        assert len(pub["pubkey_ed25519"]) == 64  # 32 bytes hex

    def test_from_export_creates_public_only(self):
        identity = NodeIdentity.generate()
        pub = identity.export_public()
        remote = NodeIdentity.from_export(pub)

        assert remote.node_id == identity.node_id
        assert remote.signing_key is None
        assert remote.box_private is None

    def test_public_only_can_verify(self):
        identity = NodeIdentity.generate()
        pub = identity.export_public()
        remote = NodeIdentity.from_export(pub)

        data = b"test data"
        sig = identity.sign_message(data)
        assert remote.verify_message(data, sig) is True
