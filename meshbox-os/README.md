# MeshBox

**Decentralized encrypted mesh network over Tor — SANP protocol v5.0**

MeshBox turns any computer into an anonymous mesh node communicating over Tor Hidden Services (`.onion`). Nodes use the custom **SANP** (SAN Adaptive Network Protocol) binary protocol for encrypted P2P messaging, routing, and gossip.

```
[Alice .onion] ──SANP──▶ [Bob .onion] ──SANP──▶ [Charlie .onion]
   Ed25519 ID              relay & route            destination
```

Every node automatically:
1. **Generates a cryptographic identity** (Ed25519 + X25519)
2. **Creates a Tor hidden service** (`.onion` address)
3. **Connects to the mesh** via SANP protocol (MessagePack frames over TCP)
4. **Routes messages** using Bellman-Ford distance-vector routing
5. **Discovers peers** via Kademlia DHT + epidemic gossip

Legacy mode (WiFi/Bluetooth mesh without Tor) is still available via `meshbox daemon`.

---

## Installation

### From source (recommended)

```bash
git clone https://github.com/meshbox/meshbox.git
cd meshbox
pip install -e ".[sanp]"
```

### With all features (web UI, Bluetooth, QR, network + SANP)

```bash
pip install -e ".[all,sanp]"
```

### Install Tor

```bash
# macOS
brew install tor

# Ubuntu/Debian
sudo apt install tor

# Verify
tor --version
```

### One-line install (Linux server)

```bash
sudo bash scripts/install_meshbox.sh
```

**Requirements:** Python 3.9+, Tor — works on **Linux**, **macOS**, and **Windows** (WSL).

---

## Quick Start

```bash
# 1. Create your identity
meshbox profile create --name "Alice"

# 2. Start the SANP mesh node (Tor + P2P + API)
meshbox start

# 3. That's it. Your node is live on the mesh.
#    - Tor hidden service:  auto-generated .onion
#    - SANP protocol:       port 7777
#    - REST API:            http://127.0.0.1:8080
```

### Join an existing network with seeds

```bash
meshbox start --seeds "abc123.onion:7777,def456.onion:7777"
```

### Or use the join script

```bash
echo "abc123.onion:7777" > seeds.txt
bash scripts/add_to_network.sh seeds.txt
```

---

## Commands

### Node & Identity

| Command | Description |
|---------|-------------|
| `meshbox start` | **Start the SANP mesh node** (Tor + SANP + API) |
| `meshbox start --seeds "a.onion:7777"` | Start with custom seed nodes |
| `meshbox start -v` | Start with verbose/debug logging |
| `meshbox profile create --name NAME` | Create a cryptographic identity |
| `meshbox profile show` | Display your profile & fingerprint |
| `meshbox profile export [--format json\|qr]` | Export profile for sharing |
| `meshbox profile update [--name N] [--bio B]` | Update your profile |
| `meshbox profile delete` | Delete your identity and keys |
| `meshbox status` | Show node status |
| `meshbox config` | Show configuration and paths |

### Messaging

| Command | Description |
|---------|-------------|
| `meshbox send --to FP --message TEXT` | Send an encrypted message |
| `meshbox inbox [--unread]` | List received messages |
| `meshbox outbox` | List sent messages |
| `meshbox read MESSAGE_ID` | Read and decrypt a message |
| `meshbox delete MESSAGE_ID` | Delete a message |
| `meshbox search QUERY` | Search messages |

### Contacts & Peers

| Command | Description |
|---------|-------------|
| `meshbox contacts` | List known contacts |
| `meshbox add-contact JSON` | Add a contact (JSON or file path) |
| `meshbox remove-contact FP` | Remove a contact |
| `meshbox peers` | Show recently seen peers |
| `meshbox verify FP` | Display safety number for verification |
| `meshbox trust FP` | Show trust score for a peer |

### Tor & Network

| Command | Description |
|---------|-------------|
| `meshbox tor status` | Tor connectivity status & onion address |
| `meshbox tor peers [--active]` | List known Tor peers |
| `meshbox tor add-peer ONION` | Add a Tor peer manually |
| `meshbox tor enable` / `disable` | Toggle Tor connectivity |
| `meshbox tor directory-enable` | Enable directory node mode |
| `meshbox tor directory-status` | Show directory node info |

### Files, SOS & Channels

| Command | Description |
|---------|-------------|
| `meshbox share FILE [--to FP] [--public]` | Share an encrypted file |
| `meshbox files` | List shared/received files |
| `meshbox sos MESSAGE [--severity LEVEL]` | Broadcast an SOS alert |
| `meshbox sos-list` | List active SOS alerts |
| `meshbox channel list` | List discussion channels |
| `meshbox channel create --name NAME` | Create a channel |
| `meshbox channel post ID --message TEXT` | Post to a channel |
| `meshbox channel view ID` | View channel messages |

### Other

| Command | Description |
|---------|-------------|
| `meshbox daemon` | Start legacy WiFi/BT mesh daemon |
| `meshbox web [--port PORT]` | Start the web UI (Flask) |
| `meshbox settings [--set KEY VALUE]` | View/update settings |
| `meshbox update [--check]` | Check for updates |
| `meshbox cleanup` | Clean up expired data |

---

## REST API

When `meshbox start` is running, a REST API is available on `http://127.0.0.1:8080`:

```bash
# Node info
curl http://127.0.0.1:8080/api/v1/node/info

# Node statistics
curl http://127.0.0.1:8080/api/v1/node/stats

# List connected peers
curl http://127.0.0.1:8080/api/v1/peers

# Send a message
curl -X POST http://127.0.0.1:8080/api/v1/message/send \
  -H "Content-Type: application/json" \
  -d '{"to": "<node_id>", "payload": "Hello!"}'

# Network topology
curl http://127.0.0.1:8080/api/v1/network/topology

# Routing table
curl http://127.0.0.1:8080/api/v1/routing/table

# Publish to gossip
curl -X POST http://127.0.0.1:8080/api/v1/gossip/publish \
  -H "Content-Type: application/json" \
  -d '{"topic": "general", "data": "hello mesh"}'

# Health check
curl http://127.0.0.1:8080/api/v1/health

# WebSocket live logs
wscat -c ws://127.0.0.1:8080/ws/logs
```

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    MeshBox CLI (Click)                        │
├──────────────────────────────────────────────────────────────┤
│  meshbox start  │  meshbox daemon  │  meshbox web (Flask)    │
├─────────────────┴──────────────────┴─────────────────────────┤
│                  MeshBox SANP Daemon                          │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────────────┐  │
│  │ Identity │ │ SANP     │ │ Gossip   │ │ REST API       │  │
│  │ Ed25519  │ │ Protocol │ │ Engine   │ │ (FastAPI)      │  │
│  │ X25519   │ │ Router   │ │ DHT      │ │ :8080          │  │
│  └──────────┘ └──────────┘ └──────────┘ └────────────────┘  │
├──────────────────────────────────────────────────────────────┤
│               Tor Hidden Service (.onion)                     │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────────────┐ │
│  │ Tor Manager  │ │ SOCKS5 Proxy │ │ Rendezvous Service   │ │
│  │ (stem)       │ │ (PySocks)    │ │ (seedless discovery) │ │
│  └──────────────┘ └──────────────┘ └──────────────────────┘ │
├──────────────────────────────────────────────────────────────┤
│  Legacy: WiFi (UDP/TCP) │ Bluetooth LE (opt) │ Storage (SQL) │
└──────────────────────────────────────────────────────────────┘
```

### Module Map

| Module | Path | Description |
|--------|------|-------------|
| **Identity** | `meshbox/crypto/node_identity.py` | Ed25519 signing, X25519 DH, node_id, encrypted storage |
| **SANP Protocol** | `meshbox/sanp/protocol.py` | Binary frames (MessagePack), handshake, PFS encryption |
| **Router** | `meshbox/sanp/router.py` | Bellman-Ford distance-vector routing, max 20 hops |
| **Gossip** | `meshbox/sanp/gossip.py` | Epidemic pub/sub, dedup cache, configurable fan-out |
| **Peer Manager** | `meshbox/sanp/peer_manager.py` | Peer tracking, keepalive, blacklisting |
| **Tor Manager** | `meshbox/tor_service/tor_manager.py` | Tor lifecycle, hidden service, SOCKS5 connections |
| **SANP Server** | `meshbox/node/sanp_server.py` | Asyncio TCP server, rate limiting, session management |
| **Daemon** | `meshbox/node/meshbox_daemon.py` | Orchestrator: ties all modules together |
| **Bootstrap** | `meshbox/node/bootstrap.py` | Seed connection, network join |
| **DHT** | `meshbox/node/dht.py` | Kademlia DHT (K=20, 256-bit XOR space) |
| **Rendezvous** | `meshbox/node/rendezvous.py` | Seedless discovery via DHT |
| **REST API** | `meshbox/api/rest_api.py` | FastAPI endpoints + WebSocket logs |
| **Legacy CLI** | `meshbox/cli.py` | Click CLI (all commands) |
| **Legacy Daemon** | `meshbox/daemon.py` | WiFi/BT mesh daemon |

---

## Docker

```bash
cd docker

# Single node
docker compose up -d

# Check logs
docker compose logs -f

# Multi-node simulation
docker compose --profile simulation up --scale meshbox-sim=5
```

The Docker image includes Tor and exposes ports `7777` (SANP) and `8080` (API).

---

## Network Simulation

Test a local mesh without Tor:

```bash
python scripts/simulate_network.py --nodes 5
```

This spawns N nodes on localhost with direct TCP connections, mesh routing, and test messages.

---

## Security

| Layer | Technology |
|-------|------------|
| **Identity** | Ed25519 signing keys (256-bit) |
| **Key exchange** | X25519 Diffie-Hellman with Perfect Forward Secrecy |
| **Encryption** | XSalsa20-Poly1305 (NaCl/libsodium) |
| **Key derivation** | Argon2id (password-protected identity storage) |
| **Transport** | Tor Hidden Services (`.onion` — no IP exposure) |
| **Routing** | Bellman-Ford with 10-min route expiry |
| **Anti-spam** | Rate limiting (100 frames/min per peer) + blacklist |
| **Protocol** | SANP binary frames with Ed25519 signatures |
| **Storage** | Private keys stored with `0600` permissions |

---

## Configuration

Data is stored in `~/.meshbox/` by default. Override with:

```bash
export MESHBOX_DATA_DIR=/path/to/data
```

Or pass `--data-dir` to the start command:

```bash
meshbox start --data-dir /path/to/data
```

### Optional Dependencies

```bash
pip install 'meshbox[sanp]'       # SANP protocol (Tor mesh)
pip install 'meshbox[web]'        # Web UI (Flask)
pip install 'meshbox[bluetooth]'  # Bluetooth LE support
pip install 'meshbox[qr]'         # QR code generation
pip install 'meshbox[network]'    # Advanced networking (zeroconf)
pip install 'meshbox[tor]'        # Tor only (stem + PySocks)
pip install 'meshbox[all,sanp]'   # Everything
```

---

## Development

```bash
git clone https://github.com/meshbox/meshbox.git
cd meshbox
python -m venv .venv
source .venv/bin/activate
pip install -e ".[sanp]"

# Run tests (80 tests)
python -m pytest tests/ -v

# Verify
meshbox --help
meshbox --version
```

---

## License

MIT License
