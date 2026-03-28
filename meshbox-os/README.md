# MeshBox

**Decentralized encrypted mesh communication CLI.**

MeshBox turns any computer into a mesh node that communicates via WiFi and Bluetooth. When the internet goes down, users can keep sending end-to-end encrypted messages through a decentralized mesh network using store-and-forward.

```
[Alice] ---WiFi/BT---> [Bob] ---WiFi/BT---> [Charlie]
  "msg for Charlie"      stores & relays      receives the message
```

When two MeshBox nodes come within WiFi/Bluetooth range, they automatically:
1. **Exchange profiles** (public key, identity)
2. **Sync encrypted messages** they carry
3. **Forward messages** destined for others (store-and-forward)

Only the intended recipient can decrypt their messages thanks to asymmetric encryption.

## Installation (one-line)

```bash
pip install meshbox
```

With all optional features (web UI, Bluetooth, QR codes):

```bash
pip install 'meshbox[all]'
```

Or install from source:

```bash
git clone https://github.com/meshbox/meshbox.git
cd meshbox
pip install -e '.[all]'
```

**Requirements:** Python 3.9+ — works on **Linux**, **macOS**, and **Windows**.

## Quick Start

```bash
# Create your identity
meshbox profile create --name "Alice"

# Send an encrypted message
meshbox send --to <fingerprint> --message "Hello Bob!"

# Check your inbox
meshbox inbox

# Read a message
meshbox read <message_id>

# Start the mesh daemon (peer discovery + message relay)
meshbox daemon

# Start the web UI
meshbox web
```

## Commands

| Command | Description |
|---------|-------------|
| `meshbox profile create --name NAME` | Create a cryptographic identity |
| `meshbox profile show` | Display your profile |
| `meshbox profile export [--format json\|qr]` | Export profile for sharing |
| `meshbox profile update [--name N] [--bio B]` | Update your profile |
| `meshbox profile delete` | Delete your identity and keys |
| `meshbox send --to FP --message TEXT` | Send an encrypted message |
| `meshbox inbox [--unread]` | List received messages |
| `meshbox outbox` | List sent messages |
| `meshbox read MESSAGE_ID` | Read and decrypt a message |
| `meshbox delete MESSAGE_ID` | Delete a message |
| `meshbox search QUERY` | Search messages |
| `meshbox contacts` | List known contacts |
| `meshbox add-contact JSON` | Add a contact (JSON or file path) |
| `meshbox remove-contact FP` | Remove a contact |
| `meshbox share FILE [--to FP] [--public]` | Share an encrypted file |
| `meshbox files` | List shared/received files |
| `meshbox sos MESSAGE [--severity LEVEL]` | Broadcast an SOS alert |
| `meshbox sos-list` | List active SOS alerts |
| `meshbox channel list` | List discussion channels |
| `meshbox channel create --name NAME` | Create a channel |
| `meshbox channel post ID --message TEXT` | Post to a channel |
| `meshbox channel view ID` | View channel messages |
| `meshbox peers` | Show recently seen peers |
| `meshbox status` | Show node status |
| `meshbox config` | Show configuration and paths |
| `meshbox cleanup` | Clean up expired data |
| `meshbox daemon [--log-level LEVEL]` | Start the mesh network daemon |
| `meshbox web [--port PORT] [--public]` | Start the web UI |

## Architecture

```
┌─────────────────────────────────────────────┐
│              MeshBox CLI                     │
├─────────────────────────────────────────────┤
│  CLI (Click)   │  Web UI (Flask, optional)  │
├─────────────────────────────────────────────┤
│         MeshBox Daemon (meshboxd)           │
├──────────┬──────────┬───────────┬───────────┤
│ Profiles │ Crypto   │ Network   │ Storage   │
│ Manager  │ Engine   │ Manager   │ Engine    │
├──────────┴──────────┴───────────┴───────────┤
│     WiFi (UDP/TCP)   │  Bluetooth LE (opt)  │
└─────────────────────────────────────────────┘
```

## Features

- **Offline-first** — WiFi ad-hoc + Bluetooth Low Energy
- **E2E encryption** — Curve25519 keys + XSalsa20-Poly1305 (NaCl/libsodium)
- **Decentralized** — No central server, every node is autonomous
- **Store-and-forward** — Messages hop node-to-node until delivered
- **Cryptographic identity** — Unique Ed25519 keypair per user
- **File sharing** — E2E encrypted files up to 10 MB
- **SOS alerts** — Emergency broadcast with severity levels
- **Channels** — Group discussion boards
- **QR codes** — Share your profile via QR code
- **Web UI** — Optional local dashboard (Flask)
- **Anti-spam** — Proof-of-work (Hashcash SHA-256)
- **Auto-expiry** — Messages have configurable TTL
- **Cross-platform** — Linux, macOS, Windows

## Configuration

Data is stored in `~/.meshbox/` by default. Override with:

```bash
export MESHBOX_DATA_DIR=/path/to/data
```

## Optional Dependencies

Install only what you need:

```bash
pip install 'meshbox[web]'        # Web UI (Flask)
pip install 'meshbox[bluetooth]'  # Bluetooth LE support
pip install 'meshbox[qr]'         # QR code generation
pip install 'meshbox[network]'    # Advanced networking
pip install 'meshbox[all]'        # Everything
```

## Security

- Curve25519 (256-bit) keys per user
- XSalsa20-Poly1305 encryption (NaCl/libsodium)
- Ed25519 signatures for authenticity
- No plaintext data on the network
- Auto-expiring messages (configurable TTL)
- Private keys stored with restricted permissions (0600)

## Development

```bash
git clone https://github.com/meshbox/meshbox.git
cd meshbox
python -m venv .venv
source .venv/bin/activate   # Linux/macOS
# .venv\Scripts\activate    # Windows
pip install -e '.[all]'

# Verify
meshbox --help
meshbox --version
python -m compileall meshbox
```

## License

MIT License
