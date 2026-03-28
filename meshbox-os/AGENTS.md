# AGENTS.md

## Mission

This repository implements MeshBox: a decentralized, encrypted, offline-first messaging CLI.
WiFi + Bluetooth mesh, store-and-forward protocol.

Goal: deliver useful changes without breaking:
- the CLI (`meshbox ...`)
- the daemon (`meshbox daemon`)
- the web UI (`meshbox web`)
- pip installation (`pip install meshbox`)

## Code structure

- `meshbox/cli.py`: CLI commands (profile, messages, files, SOS, channels, daemon, web).
- `meshbox/daemon.py`: network orchestration + sync + cleanup.
- `meshbox/web/__init__.py`: Flask server and HTML/API routes.
- `meshbox/network.py`: WiFi/BLE discovery and TCP transport.
- `meshbox/storage.py`: SQLite storage (schema and data access).
- `meshbox/crypto.py`: identities, encryption, signatures, PoW.
- `meshbox/profiles.py`: local profile and contact management.
- `meshbox/files.py`: encrypted file sharing.
- `meshbox/config.py`: cross-platform paths and configuration.
- `meshbox/web/templates/`: Jinja2 HTML templates.
- `meshbox/web/static/`: CSS and JS assets.
- `pyproject.toml`: package metadata and dependencies.

## Local development

Prerequisites:
- Python `>=3.9`

Setup:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[all]'
```

Useful commands:

```bash
meshbox --help
meshbox profile create --name "Test"
meshbox status
meshbox daemon
meshbox web
```

## Constraints

- Keep cross-platform compatibility (Linux, macOS, Windows).
- Data directory: `~/.meshbox/` (overridable via `MESHBOX_DATA_DIR`).
- Preserve SQLite schema compatibility:
  - use `CREATE TABLE IF NOT EXISTS`, `CREATE INDEX IF NOT EXISTS`
  - do not drop columns/tables without explicit migration
- No mandatory external network dependency at runtime.
- Core dependencies: only `PyNaCl` and `click`. Everything else is optional.

## Validation before delivery

Always run:

```bash
python -m compileall meshbox
```

If you touch:
- CLI (`meshbox/cli.py`): verify `meshbox --help`.
- Web (`meshbox/web/*`): verify that `meshbox web` starts without error.
- Storage (`meshbox/storage.py`): verify DB creation on a fresh `MESHBOX_DATA_DIR`.
- Network/Daemon: verify that the daemon starts without syntax/import crash.

## Definition of done

Before closing a task:
- changes limited to what was requested
- explicit impact in the commit message
- minimal validation executed
- docs updated if user-facing behavior changed (README or this file)
