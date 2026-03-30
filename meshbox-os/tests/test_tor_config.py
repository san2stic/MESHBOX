"""Tests for meshbox.tor_service.tor_config."""

import os
from pathlib import Path

import pytest

from meshbox.tor_service.tor_config import generate_torrc, read_onion_address


class TestTorConfig:
    def test_generate_torrc(self, tmp_path):
        torrc = generate_torrc(tmp_path, socks_port=9150, control_port=9151)
        assert torrc.exists()
        content = torrc.read_text()
        assert "SocksPort 9150" in content
        assert "ControlPort 9151" in content
        assert "HiddenServiceVersion 3" in content
        assert "SafeLogging 1" in content

    def test_creates_directories(self, tmp_path):
        data_dir = tmp_path / "deep" / "path"
        generate_torrc(data_dir)
        assert (data_dir / "tor").exists()
        assert (data_dir / "tor" / "hidden_service").exists()

    def test_hidden_service_dir_permissions(self, tmp_path):
        generate_torrc(tmp_path)
        hs_dir = tmp_path / "tor" / "hidden_service"
        perms = os.stat(hs_dir).st_mode & 0o777
        assert perms == 0o700

    def test_torrc_file_permissions(self, tmp_path):
        torrc = generate_torrc(tmp_path)
        perms = os.stat(torrc).st_mode & 0o777
        assert perms == 0o600

    def test_read_onion_address_missing(self, tmp_path):
        assert read_onion_address(tmp_path) is None

    def test_read_onion_address_exists(self, tmp_path):
        hs_dir = tmp_path / "tor" / "hidden_service"
        hs_dir.mkdir(parents=True)
        (hs_dir / "hostname").write_text("abcdefghij.onion\n")
        assert read_onion_address(tmp_path) == "abcdefghij.onion"

    def test_custom_bind_port(self, tmp_path):
        torrc = generate_torrc(
            tmp_path,
            hidden_service_port=7777,
            local_bind_port=8888,
        )
        content = torrc.read_text()
        assert "HiddenServicePort 7777 127.0.0.1:8888" in content
