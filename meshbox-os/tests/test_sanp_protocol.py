"""Tests for meshbox.sanp.protocol — SANP frames and handshake."""

import asyncio
import os

import pytest

from meshbox.crypto.node_identity import NodeIdentity
from meshbox.sanp.protocol import (
    SANP_VERSION,
    MessageType,
    SANPFrame,
    SANPHandshake,
    read_frame,
    write_frame,
)


class TestSANPFrame:
    def test_create_frame(self):
        frame = SANPFrame.make(MessageType.PING)
        assert frame.version == SANP_VERSION
        assert frame.msg_type == MessageType.PING
        assert len(frame.msg_id) == 8

    def test_serialize_deserialize(self):
        frame = SANPFrame.make(MessageType.MESSAGE, {b"hello": b"world"})
        raw = frame.to_bytes()
        # Skip the 4-byte length header
        body = raw[4:]
        restored = SANPFrame.from_bytes(body)
        assert restored.msg_type == frame.msg_type
        assert restored.msg_id == frame.msg_id
        assert restored.payload == frame.payload

    def test_sign_and_validate(self):
        identity = NodeIdentity.generate()
        frame = SANPFrame.make(MessageType.PING, b"keepalive")
        frame.sign(identity.signing_key)

        assert len(frame.signature) == 64
        assert frame.validate_signature(identity.verify_key.encode()) is True

    def test_invalid_signature_rejected(self):
        id1 = NodeIdentity.generate()
        id2 = NodeIdentity.generate()

        frame = SANPFrame.make(MessageType.PING)
        frame.sign(id1.signing_key)
        assert frame.validate_signature(id2.verify_key.encode()) is False

    def test_tampered_payload_rejected(self):
        identity = NodeIdentity.generate()
        frame = SANPFrame.make(MessageType.MESSAGE, b"original")
        frame.sign(identity.signing_key)

        frame.payload = b"tampered"
        assert frame.validate_signature(identity.verify_key.encode()) is False

    def test_all_message_types(self):
        for mt in MessageType:
            frame = SANPFrame.make(mt)
            assert frame.msg_type == mt


class TestSANPHandshake:
    def test_full_handshake(self):
        alice = NodeIdentity.generate()
        bob = NodeIdentity.generate()

        hs_alice = SANPHandshake(alice)
        hs_bob = SANPHandshake(bob)

        # Alice → Bob: HELLO
        hello = hs_alice.create_hello()
        assert hello.msg_type == MessageType.HELLO

        # Bob processes HELLO, creates HELLO_ACK
        ack, bob_key = hs_bob.process_hello(hello)
        assert ack.msg_type == MessageType.HELLO_ACK
        assert len(bob_key) == 32

        # Alice processes HELLO_ACK
        alice_key = hs_alice.process_hello_ack(ack)
        assert len(alice_key) == 32

        # Both sides derive the same session key
        assert alice_key == bob_key

    def test_session_encryption(self):
        alice = NodeIdentity.generate()
        bob = NodeIdentity.generate()

        hs_a = SANPHandshake(alice)
        hs_b = SANPHandshake(bob)

        hello = hs_a.create_hello()
        ack, _ = hs_b.process_hello(hello)
        hs_a.process_hello_ack(ack)

        # Encrypt with Alice's session, decrypt with Bob's
        plaintext = b"Session encrypted message"
        ciphertext = hs_a.encrypt_session(plaintext)
        decrypted = hs_b.decrypt_session(ciphertext)
        assert decrypted == plaintext

    def test_handshake_rejects_bad_signature(self):
        alice = NodeIdentity.generate()
        bob = NodeIdentity.generate()

        hs_alice = SANPHandshake(alice)
        hello = hs_alice.create_hello()
        # Tamper with signature
        hello.signature = bytes(64)

        hs_bob = SANPHandshake(bob)
        with pytest.raises(ValueError, match="Invalid HELLO signature"):
            hs_bob.process_hello(hello)

    def test_different_handshakes_yield_different_keys(self):
        alice = NodeIdentity.generate()
        bob = NodeIdentity.generate()

        # First handshake
        hs1a = SANPHandshake(alice)
        hs1b = SANPHandshake(bob)
        hello1 = hs1a.create_hello()
        ack1, key1 = hs1b.process_hello(hello1)
        hs1a.process_hello_ack(ack1)

        # Second handshake (different ephemeral keys)
        hs2a = SANPHandshake(alice)
        hs2b = SANPHandshake(bob)
        hello2 = hs2a.create_hello()
        ack2, key2 = hs2b.process_hello(hello2)

        # Keys should differ (PFS)
        assert key1 != key2


class TestFrameIO:
    @pytest.mark.asyncio
    async def test_read_write_frame(self):
        identity = NodeIdentity.generate()
        frame = SANPFrame.make(MessageType.GOSSIP, {b"topic": b"test"})
        frame.sign(identity.signing_key)

        # Simulate stream I/O
        reader = asyncio.StreamReader()
        reader.feed_data(frame.to_bytes())
        reader.feed_eof()

        restored = await read_frame(reader)
        assert restored.msg_type == frame.msg_type
        assert restored.msg_id == frame.msg_id
        assert restored.payload == frame.payload
        assert restored.validate_signature(identity.verify_key.encode())
