"""
MeshBox CLI — SANP v5.0 command-line interface.

All networking operations go through the running SANP daemon (REST API on :8080).
Offline operations (profile, config, settings) work directly with StorageEngine.
"""

import json
import hashlib
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Optional, Union
from urllib.error import URLError
from urllib.request import Request, urlopen

import click

from meshbox import __version__
from meshbox.config import DATA_DIR, API_HOST, API_PORT, SANP_PORT
from meshbox.storage import StorageEngine


def get_data_dir() -> Path:
    """Get and ensure the data directory exists."""
    data_dir = DATA_DIR
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


def _api_url(path: str) -> str:
    """Build a local API URL."""
    return f"http://{API_HOST}:{API_PORT}{path}"


def _api_get(path: str) -> Optional[Union[dict, list]]:
    """GET request to the SANP daemon REST API."""
    try:
        req = Request(_api_url(path))
        with urlopen(req, timeout=5) as resp:
            return json.loads(resp.read())
    except (URLError, OSError, json.JSONDecodeError):
        return None


def _api_post(path: str, data: dict = None) -> Optional[dict]:
    """POST request to the SANP daemon REST API."""
    try:
        body = json.dumps(data or {}).encode("utf-8")
        req = Request(_api_url(path), data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        with urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except (URLError, OSError, json.JSONDecodeError):
        return None


def _api_delete(path: str) -> Optional[dict]:
    """DELETE request to the SANP daemon REST API."""
    try:
        req = Request(_api_url(path), method="DELETE")
        with urlopen(req, timeout=5) as resp:
            return json.loads(resp.read())
    except (URLError, OSError, json.JSONDecodeError):
        return None


def _api_put(path: str, data: dict = None) -> Optional[dict]:
    """PUT request to the SANP daemon REST API."""
    try:
        body = json.dumps(data or {}).encode("utf-8")
        req = Request(_api_url(path), data=body, method="PUT")
        req.add_header("Content-Type", "application/json")
        with urlopen(req, timeout=5) as resp:
            return json.loads(resp.read())
    except (URLError, OSError, json.JSONDecodeError):
        return None


def _daemon_running() -> bool:
    """Check if the SANP daemon is reachable."""
    return _api_get("/api/v1/health") is not None


def get_components():
    """Initialize core components (direct storage access for offline use)."""
    data_dir = get_data_dir()
    storage = StorageEngine(data_dir / "meshbox.db")
    return storage


# ═══════════════════════════════════════════════════════════════
# Main CLI group
# ═══════════════════════════════════════════════════════════════

@click.group()
@click.version_option(version=__version__, prog_name="MeshBox")
def cli():
    """MeshBox — Decentralized encrypted mesh communication via SANP protocol.

    \b
    Anonymous P2P messaging over Tor hidden services using the SANP
    (SAN Adaptive Network Protocol) binary protocol.

    \b
    Quick start:
      meshbox start                              # Start the SANP node
      meshbox send --to <node_id> --message "Hello!"
      meshbox inbox
    """
    pass


# ═══════════════════════════════════════════════════════════════
# Profile commands
# ═══════════════════════════════════════════════════════════════

@cli.group()
def profile():
    """Manage your cryptographic identity and profile."""
    pass


@profile.command("create")
@click.option("--name", "-n", required=True, help="Your name or alias")
@click.option("--bio", "-b", default="", help="Short bio/description")
def profile_create(name, bio):
    """Create a new profile with a cryptographic identity."""
    # If daemon is running, use API
    if _daemon_running():
        result = _api_post("/api/v1/profile", {"name": name, "bio": bio})
        if result:
            click.echo("Profile created via SANP daemon!")
            click.echo(f"  Name:        {name}")
            click.echo(f"  Fingerprint: {result.get('fingerprint', 'N/A')}")
            click.echo()
            click.echo("Your SANP node is running. Identity already active.")
            return
        click.echo("Warning: daemon running but profile creation failed, trying offline.")

    # Offline: create profile via legacy ProfileManager
    try:
        from meshbox.profiles import ProfileManager
        storage = get_components()
        profile_mgr = ProfileManager(storage, get_data_dir() / "keys")

        if profile_mgr.is_initialized:
            click.echo("Error: A profile already exists.")
            click.echo("Delete it first with: meshbox profile delete")
            sys.exit(1)

        p = profile_mgr.create_profile(name, bio)
        click.echo("Profile created!")
        click.echo(f"  Name:        {p['name']}")
        click.echo(f"  Fingerprint: {p['fingerprint']}")
        click.echo(f"  Verify key:  {p['verify_key'][:20]}...")
        click.echo()
        click.echo("Start the SANP node with: meshbox start")
    except ImportError:
        click.echo("Error: Profile creation requires meshbox start or legacy crypto modules.")
        sys.exit(1)


@profile.command("show")
def profile_show():
    """Display the local profile."""
    # Try API first
    if _daemon_running():
        p = _api_get("/api/v1/profile")
        if p:
            click.echo("=== MeshBox Profile (SANP) ===")
            click.echo(f"  Name:        {p.get('name', 'N/A')}")
            click.echo(f"  Fingerprint: {p.get('fingerprint', 'N/A')}")
            click.echo(f"  Bio:         {p.get('bio', '')}")
            click.echo(f"  Public key:  {p.get('verify_key', '')[:32]}...")
            click.echo(f"  Box key:     {p.get('box_public_key', '')[:32]}...")
            ts = p.get('created_at', 0)
            if ts:
                click.echo(f"  Created:     {time.strftime('%Y-%m-%d %H:%M', time.localtime(ts))}")
            return

    # Offline fallback
    storage = get_components()
    p = storage.get_local_profile()
    if not p:
        click.echo("No profile found. Start the SANP node: meshbox start")
        sys.exit(1)

    click.echo("=== MeshBox Profile ===")
    click.echo(f"  Name:        {p['name']}")
    click.echo(f"  Fingerprint: {p['fingerprint']}")
    click.echo(f"  Bio:         {p.get('bio', '')}")
    click.echo(f"  Public key:  {p['verify_key'][:32]}...")
    click.echo(f"  Box key:     {p['box_public_key'][:32]}...")
    click.echo(f"  Created:     {time.strftime('%Y-%m-%d %H:%M', time.localtime(p['created_at']))}")


@profile.command("export")
@click.option("--format", "-f", "fmt", type=click.Choice(["json", "qr"]), default="json",
              help="Export format")
def profile_export(fmt):
    """Export your profile for sharing."""
    # Try API first
    if _daemon_running():
        data = _api_get("/api/v1/profile")
        if data:
            # Filter to shareable fields
            share = {k: data[k] for k in ("fingerprint", "name", "verify_key", "box_public_key", "bio") if k in data}
            if fmt == "json":
                click.echo(json.dumps(share, indent=2))
                return
            elif fmt == "qr":
                try:
                    import qrcode
                    qr = qrcode.QRCode(version=1, box_size=1, border=1)
                    qr.add_data(json.dumps(share))
                    qr.make(fit=True)
                    qr.print_ascii(invert=True)
                except ImportError:
                    click.echo("QR module not installed. Install with: pip install 'meshbox[qr]'")
                    click.echo("Or use: meshbox profile export --format json")
                return

    # Offline fallback
    storage = get_components()
    p = storage.get_local_profile()
    if not p:
        click.echo("No profile found. Start the SANP node: meshbox start")
        sys.exit(1)

    share = {k: p[k] for k in ("fingerprint", "name", "verify_key", "box_public_key", "bio") if k in p}
    if fmt == "json":
        click.echo(json.dumps(share, indent=2))
    elif fmt == "qr":
        try:
            import qrcode
            qr = qrcode.QRCode(version=1, box_size=1, border=1)
            qr.add_data(json.dumps(share))
            qr.make(fit=True)
            qr.print_ascii(invert=True)
        except ImportError:
            click.echo("QR module not installed. Install with: pip install 'meshbox[qr]'")
            click.echo("Or use: meshbox profile export --format json")


@profile.command("update")
@click.option("--name", "-n", help="New name")
@click.option("--bio", "-b", help="New bio")
def profile_update(name, bio):
    """Update your profile."""
    payload = {}
    if name:
        payload["name"] = name
    if bio:
        payload["bio"] = bio
    if not payload:
        click.echo("Nothing to update. Use --name or --bio.")
        return

    if _daemon_running():
        resp = _api_put("/api/v1/profile", payload)
        if resp:
            click.echo("Profile updated via SANP daemon.")
            return

    # Offline fallback
    storage = get_components()
    p = storage.get_local_profile()
    if not p:
        click.echo("No profile found.")
        sys.exit(1)
    if name:
        p["name"] = name
    if bio:
        p["bio"] = bio
    storage.save_profile(p)
    click.echo("Profile updated (offline).")


@profile.command("delete")
@click.confirmation_option(prompt="This will delete your cryptographic identity. Are you sure?")
def profile_delete():
    """Delete your profile and cryptographic keys."""
    data_dir = get_data_dir()
    keys_dir = data_dir / "keys"
    if keys_dir.exists():
        for f in keys_dir.iterdir():
            f.unlink()
        keys_dir.rmdir()

    storage = get_components()
    local = storage.get_local_profile()
    if local:
        with storage._transaction() as conn:
            conn.execute("DELETE FROM profiles WHERE is_local = 1")

    click.echo("Profile and keys deleted.")


# ═══════════════════════════════════════════════════════════════
# Messaging commands
# ═══════════════════════════════════════════════════════════════

@cli.command("send")
@click.option("--to", "-t", "recipient", required=True, help="Recipient fingerprint")
@click.option("--message", "-m", "text", required=True, help="Message text")
@click.option("--disappear", is_flag=True, help="Message disappears after being read")
@click.option("--disappear-timer", type=int, default=0, help="Auto-delete after N seconds (0=disabled)")
@click.option("--onion", is_flag=True, help="Route via onion layers for sender anonymity")
def send_message(recipient, text, disappear, disappear_timer, onion):
    """Send an encrypted message via SANP.

    \b
    Options:
      --disappear          Message is deleted after it is read
      --disappear-timer N  Message auto-deletes after N seconds
      --onion              Route message through onion layers for anonymity
    """
    if not _daemon_running():
        click.echo("Error: SANP daemon is not running.")
        click.echo("Start it with: meshbox start")
        sys.exit(1)

    payload = {
        "recipient_fingerprint": recipient,
        "plaintext": text,
        "disappear_after_read": disappear,
        "disappear_timer": disappear_timer,
    }
    resp = _api_post("/api/v1/message/send", payload)
    if not resp:
        click.echo("Failed to send message. Check daemon logs.")
        sys.exit(1)

    click.echo("Message encrypted and sent via SANP.")
    click.echo(f"  ID:        {resp.get('message_id', 'N/A')}")
    click.echo(f"  To:        {recipient}")
    click.echo(f"  Status:    {resp.get('status', 'queued')}")
    if disappear:
        click.echo("  Mode:      Disappears after read")
    if disappear_timer > 0:
        click.echo(f"  Timer:     Auto-deletes in {disappear_timer}s")
    if onion:
        click.echo("  Routing:   Onion (anonymous)")


@cli.command("inbox")
@click.option("--unread", "-u", is_flag=True, help="Show only unread messages")
def inbox(unread):
    """Show received messages."""
    # Try API first
    if _daemon_running():
        params = "?unread=true" if unread else ""
        messages = _api_get(f"/api/v1/messages/inbox{params}")
        if messages is not None:
            msgs = messages if isinstance(messages, list) else messages.get("messages", [])
            if not msgs:
                click.echo("No messages." if not unread else "No unread messages.")
                return
            click.echo(f"=== Inbox ({len(msgs)} messages) ===")
            click.echo()
            for msg in msgs:
                sender = msg.get("sender_name", msg.get("sender_fingerprint", "?")[:12])
                status = "*" if not msg.get("read") else " "
                ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(msg.get("timestamp", 0)))
                click.echo(f"  [{status}] [{ts}] From: {sender}")
                click.echo(f"       ID: {msg.get('message_id', '?')}")
            return

    # Offline fallback
    storage = get_components()
    p = storage.get_local_profile()
    if not p:
        click.echo("No profile found.")
        sys.exit(1)

    messages = storage.get_inbox(p["fingerprint"])
    if unread:
        messages = [m for m in messages if not m.get("read")]

    if not messages:
        click.echo("No messages." if not unread else "No unread messages.")
        return

    click.echo(f"=== Inbox ({len(messages)} messages) ===")
    click.echo()
    for msg in messages:
        sender = storage.get_profile(msg["sender_fingerprint"])
        sender_name = sender["name"] if sender else msg["sender_fingerprint"]
        status = "*" if not msg.get("read") else " "
        ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(msg["timestamp"]))
        click.echo(f"  [{status}] [{ts}] From: {sender_name}")
        click.echo(f"       ID: {msg['message_id']}")


@cli.command("outbox")
def outbox():
    """Show sent messages."""
    if _daemon_running():
        messages = _api_get("/api/v1/messages/outbox")
        if messages is not None:
            msgs = messages if isinstance(messages, list) else messages.get("messages", [])
            if not msgs:
                click.echo("No sent messages.")
                return
            click.echo(f"=== Outbox ({len(msgs)} messages) ===")
            click.echo()
            for msg in msgs:
                name = msg.get("recipient_name", msg.get("recipient_fingerprint", "?")[:12])
                ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(msg.get("timestamp", 0)))
                click.echo(f"  [{ts}] To: {name}")
                click.echo(f"       ID: {msg.get('message_id', '?')}")
            return

    storage = get_components()
    p = storage.get_local_profile()
    if not p:
        click.echo("No profile found.")
        sys.exit(1)

    messages = storage.get_outbox(p["fingerprint"])
    if not messages:
        click.echo("No sent messages.")
        return

    click.echo(f"=== Outbox ({len(messages)} messages) ===")
    click.echo()
    for msg in messages:
        recipient = storage.get_profile(msg["recipient_fingerprint"])
        name = recipient["name"] if recipient else msg["recipient_fingerprint"]
        ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(msg["timestamp"]))
        click.echo(f"  [{ts}] To: {name}")
        click.echo(f"       ID: {msg['message_id']}")


@cli.command("read")
@click.argument("message_id")
def read_message(message_id):
    """Read a message."""
    if _daemon_running():
        msg = _api_get(f"/api/v1/messages/{message_id}")
        if msg:
            sender = msg.get("sender_name", msg.get("sender_fingerprint", "?")[:12])
            ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(msg.get("timestamp", 0)))
            click.echo(f"=== Message from {sender} ===")
            click.echo(f"Date:  {ts}")
            click.echo(f"ID:    {message_id}")
            click.echo("---")
            click.echo(msg.get("plaintext", msg.get("content", "[encrypted]")))
            return

    storage = get_components()
    p = storage.get_local_profile()
    if not p:
        click.echo("No profile found.")
        sys.exit(1)

    all_inbox = storage.get_inbox(p["fingerprint"])
    target = None
    for msg in all_inbox:
        if msg["message_id"] == message_id:
            target = msg
            break

    if not target:
        click.echo("Message not found.")
        sys.exit(1)

    sender = storage.get_profile(target["sender_fingerprint"])
    sender_name = sender["name"] if sender else target["sender_fingerprint"]
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(target["timestamp"]))

    click.echo(f"=== Message from {sender_name} ===")
    click.echo(f"Date:  {ts}")
    click.echo(f"ID:    {message_id}")
    click.echo("---")
    click.echo(target.get("plaintext", "[encrypted - daemon required to decrypt]"))
    storage.mark_read(message_id)


@cli.command("delete")
@click.argument("message_id")
def delete_message(message_id):
    """Delete a message by ID."""
    if _daemon_running():
        resp = _api_delete(f"/api/v1/messages/{message_id}")
        if resp is not None:
            click.echo(f"Message {message_id} deleted.")
            return
    storage = get_components()
    storage.delete_message(message_id)
    click.echo(f"Message {message_id} deleted.")


# ═══════════════════════════════════════════════════════════════
# Contact commands
# ═══════════════════════════════════════════════════════════════

@cli.command("contacts")
def list_contacts():
    """List known contacts."""
    if _daemon_running():
        contacts = _api_get("/api/v1/contacts")
        if contacts is not None:
            items = contacts if isinstance(contacts, list) else contacts.get("contacts", [])
            if not items:
                click.echo("No contacts. Start the SANP node to discover peers.")
                return
            click.echo(f"=== Contacts ({len(items)}) ===")
            for c in items:
                last = time.strftime("%Y-%m-%d %H:%M", time.localtime(c.get("last_seen", 0)))
                click.echo(f"  {c.get('name', '?')}")
                click.echo(f"    Fingerprint: {c.get('fingerprint', '?')}")
                click.echo(f"    Last seen:   {last}")
                if c.get("bio"):
                    click.echo(f"    Bio:         {c['bio']}")
                click.echo()
            return

    storage = get_components()
    contacts = storage.get_all_profiles()
    contacts = [c for c in contacts if not c.get("is_local")]
    if not contacts:
        click.echo("No contacts. Start the SANP node to discover peers.")
        return

    click.echo(f"=== Contacts ({len(contacts)}) ===")
    for c in contacts:
        last = time.strftime("%Y-%m-%d %H:%M", time.localtime(c.get("last_seen", 0)))
        click.echo(f"  {c['name']}")
        click.echo(f"    Fingerprint: {c['fingerprint']}")
        click.echo(f"    Last seen:   {last}")
        if c.get("bio"):
            click.echo(f"    Bio:         {c['bio']}")
        click.echo()


@cli.command("add-contact")
@click.argument("json_data")
def add_contact(json_data):
    """Add a contact manually (JSON string or file path)."""
    try:
        if os.path.isfile(json_data):
            with open(json_data) as f:
                data = json.load(f)
        else:
            data = json.loads(json_data)
    except (json.JSONDecodeError, FileNotFoundError):
        click.echo("Error: Invalid JSON or file not found.")
        sys.exit(1)

    required = ["fingerprint", "name", "verify_key", "box_public_key"]
    for field in required:
        if field not in data:
            click.echo(f"Missing field: {field}")
            sys.exit(1)

    if _daemon_running():
        resp = _api_post("/api/v1/contacts", data)
        if resp:
            click.echo(f"Contact added via SANP: {data['name']} ({data['fingerprint']})")
            return

    storage = get_components()
    data.setdefault("is_local", 0)
    data.setdefault("last_seen", int(time.time()))
    storage.save_profile(data)
    click.echo(f"Contact added: {data['name']} ({data['fingerprint']})")


@cli.command("remove-contact")
@click.argument("fingerprint")
def remove_contact(fingerprint):
    """Remove a contact by fingerprint."""
    if _daemon_running():
        resp = _api_delete(f"/api/v1/contacts/{fingerprint}")
        if resp is not None:
            click.echo(f"Contact {fingerprint} removed.")
            return
    storage = get_components()
    storage.delete_contact(fingerprint)
    click.echo(f"Contact {fingerprint} removed.")


# ═══════════════════════════════════════════════════════════════
# File sharing commands
# ═══════════════════════════════════════════════════════════════

@cli.command("share")
@click.argument("filepath", type=click.Path(exists=True))
@click.option("--to", "-t", "recipient", default="", help="Recipient fingerprint")
@click.option("--public", "-p", is_flag=True, help="Make file public (visible to all)")
@click.option("--desc", "-d", default="", help="Description")
def share_file(filepath, recipient, public, desc):
    """Share an encrypted file over the SANP mesh network."""
    import base64

    with open(filepath, "rb") as f:
        file_data = f.read()

    filename = os.path.basename(filepath)
    file_size = len(file_data)

    storage = get_components()
    p = storage.get_local_profile()
    if not p:
        click.echo("No profile found. Start the SANP node: meshbox start")
        sys.exit(1)

    file_id = str(uuid.uuid4())
    file_hash = hashlib.sha256(file_data).hexdigest()

    # Save to local storage
    data_dir = get_data_dir()
    files_dir = data_dir / "files"
    files_dir.mkdir(exist_ok=True)
    (files_dir / file_id).write_bytes(file_data)

    storage.save_shared_file({
        "file_id": file_id,
        "filename": filename,
        "file_size": file_size,
        "file_hash": file_hash,
        "sender_fingerprint": p["fingerprint"],
        "recipient_fingerprint": recipient,
        "description": desc,
        "is_public": 1 if public else 0,
    })

    # Notify via SANP gossip if daemon running
    if _daemon_running():
        _api_post("/api/v1/files/share", {
            "file_id": file_id,
            "filename": filename,
            "file_size": file_size,
            "file_hash": file_hash,
            "recipient_fingerprint": recipient,
            "description": desc,
            "is_public": public,
        })

    size_str = _format_size(file_size)
    click.echo(f"File shared: {filename} ({size_str})")
    click.echo(f"  ID: {file_id}")
    if public:
        click.echo("  Mode: PUBLIC")
    elif recipient:
        click.echo(f"  To: {recipient}")


@cli.command("files")
def list_files():
    """List shared files."""
    if _daemon_running():
        files = _api_get("/api/v1/files")
        if files is not None:
            items = files if isinstance(files, list) else files.get("files", [])
            if not items:
                click.echo("No shared files.")
                return
            click.echo(f"=== Files ({len(items)}) ===")
            for f in items:
                size = _format_size(f.get("file_size", 0))
                click.echo(f"  [{f.get('file_id', '?')[:8]}] {f.get('filename', '?')} ({size})")
            return

    storage = get_components()
    files = storage.get_shared_files()
    if not files:
        click.echo("No shared files.")
        return

    click.echo(f"=== Files ({len(files)}) ===")
    for f in files:
        size = _format_size(f.get("file_size", 0))
        click.echo(f"  [{f['file_id'][:8]}] {f['filename']} ({size})")


# ═══════════════════════════════════════════════════════════════
# SOS commands
# ═══════════════════════════════════════════════════════════════

@cli.command("sos")
@click.argument("message")
@click.option("--severity", "-s", type=click.Choice(["low", "high", "critical"]), default="high",
              help="Alert severity level")
def sos_alert(message, severity):
    """Broadcast an SOS alert over the SANP mesh network."""
    if _daemon_running():
        resp = _api_post("/api/v1/sos", {"message": message, "severity": severity})
        if resp:
            click.echo("SOS ALERT BROADCAST via SANP gossip")
            click.echo(f"  Severity: {severity.upper()}")
            click.echo(f"  Message:  {message}")
            click.echo(f"  ID:       {resp.get('alert_id', '?')[:8]}")
            return

    # Offline: save locally for relay when daemon starts
    storage = get_components()
    p = storage.get_local_profile()
    fp = p["fingerprint"] if p else "unknown"
    alert = {
        "alert_id": str(uuid.uuid4()),
        "sender_fingerprint": fp,
        "message": message,
        "severity": severity,
        "timestamp": int(time.time()),
        "ttl": 86400,
    }
    storage.save_sos_alert(alert)
    click.echo("SOS ALERT saved locally (will broadcast when node starts)")
    click.echo(f"  Severity: {severity.upper()}")
    click.echo(f"  Message:  {message}")
    click.echo(f"  ID:       {alert['alert_id'][:8]}")


@cli.command("sos-list")
def sos_list():
    """List active SOS alerts."""
    if _daemon_running():
        alerts = _api_get("/api/v1/sos")
        if alerts is not None:
            items = alerts if isinstance(alerts, list) else alerts.get("alerts", [])
            if not items:
                click.echo("No active SOS alerts.")
                return
            click.echo(f"=== Active SOS Alerts ({len(items)}) ===")
            for a in items:
                name = a.get("sender_name", a.get("sender_fingerprint", "?")[:12])
                ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(a.get("timestamp", 0)))
                click.echo(f"  [{a.get('severity', '?').upper()}] {a.get('message', '')}")
                click.echo(f"    From: {name} | {ts} | ID: {a.get('alert_id', '?')[:8]}")
            return

    storage = get_components()
    alerts = storage.get_active_sos()
    if not alerts:
        click.echo("No active SOS alerts.")
        return

    click.echo(f"=== Active SOS Alerts ({len(alerts)}) ===")
    for a in alerts:
        name = a.get("sender_name", a["sender_fingerprint"][:12])
        ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(a["timestamp"]))
        click.echo(f"  [{a['severity'].upper()}] {a['message']}")
        click.echo(f"    From: {name} | {ts} | ID: {a['alert_id'][:8]}")

# ═══════════════════════════════════════════════════════════════
# Channel commands
# ═══════════════════════════════════════════════════════════════

@cli.group("channel")
def channel_group():
    """Manage discussion channels."""
    pass


@channel_group.command("list")
def channel_list():
    """List all channels."""
    if _daemon_running():
        channels = _api_get("/api/v1/channels")
        if channels is not None:
            items = channels if isinstance(channels, list) else channels.get("channels", [])
            if not items:
                click.echo("No channels.")
                return
            click.echo(f"=== Channels ({len(items)}) ===")
            for ch in items:
                msg_count = ch.get("msg_count", 0)
                creator = ch.get("creator_name", ch.get("creator_fingerprint", "?")[:12])
                click.echo(f"  #{ch.get('name', '?')} - {msg_count} messages - by {creator}")
                if ch.get("description"):
                    click.echo(f"    {ch['description']}")
            return

    storage = get_components()
    channels = storage.get_channels()
    if not channels:
        click.echo("No channels.")
        return

    click.echo(f"=== Channels ({len(channels)}) ===")
    for ch in channels:
        msg_count = ch.get("msg_count", 0)
        creator = ch.get("creator_name", ch["creator_fingerprint"][:12])
        click.echo(f"  #{ch['name']} - {msg_count} messages - by {creator}")
        if ch.get("description"):
            click.echo(f"    {ch['description']}")


@channel_group.command("create")
@click.option("--name", "-n", required=True, help="Channel name")
@click.option("--desc", "-d", default="", help="Channel description")
def channel_create(name, desc):
    """Create a new channel."""
    if _daemon_running():
        resp = _api_post("/api/v1/channels", {"name": name, "description": desc})
        if resp:
            click.echo(f"Channel '#{name}' created via SANP (ID: {resp.get('channel_id', '?')[:8]})")
            return

    storage = get_components()
    p = storage.get_local_profile()
    if not p:
        click.echo("No profile found.")
        sys.exit(1)

    channel = {
        "channel_id": str(uuid.uuid4()),
        "name": name,
        "description": desc,
        "creator_fingerprint": p["fingerprint"],
        "is_public": 1,
    }
    storage.create_channel(channel)
    click.echo(f"Channel '#{name}' created (ID: {channel['channel_id'][:8]})")


@channel_group.command("post")
@click.argument("channel_id")
@click.option("--message", "-m", required=True, help="Message content")
def channel_post(channel_id, message):
    """Post a message to a channel."""
    if _daemon_running():
        resp = _api_post(f"/api/v1/channels/{channel_id}/post", {"content": message})
        if resp:
            click.echo(f"Posted to channel via SANP gossip.")
            return

    storage = get_components()
    p = storage.get_local_profile()
    if not p:
        click.echo("No profile found.")
        sys.exit(1)

    channel = storage.get_channel(channel_id)
    if not channel:
        click.echo("Channel not found.")
        sys.exit(1)

    storage.post_channel_message({
        "message_id": str(uuid.uuid4()),
        "channel_id": channel_id,
        "sender_fingerprint": p["fingerprint"],
        "content": message,
    })
    click.echo(f"Posted to #{channel['name']}")


@channel_group.command("view")
@click.argument("channel_id")
@click.option("--limit", "-l", default=20, help="Number of messages to show")
def channel_view(channel_id, limit):
    """View messages in a channel."""
    if _daemon_running():
        msgs = _api_get(f"/api/v1/channels/{channel_id}/messages?limit={limit}")
        ch = _api_get(f"/api/v1/channels/{channel_id}")
        ch_name = ch.get("name", channel_id[:8]) if ch else channel_id[:8]
        if msgs is not None:
            items = msgs if isinstance(msgs, list) else msgs.get("messages", [])
            click.echo(f"=== #{ch_name} ===")
            if not items:
                click.echo("  No messages yet.")
                return
            for msg in reversed(items):
                name = msg.get("sender_name", msg.get("sender_fingerprint", "?")[:12])
                ts = time.strftime("%H:%M", time.localtime(msg.get("timestamp", 0)))
                click.echo(f"  [{ts}] {name}: {msg.get('content', '')}")
            return

    storage = get_components()
    channel = storage.get_channel(channel_id)
    if not channel:
        click.echo("Channel not found.")
        sys.exit(1)

    messages = storage.get_channel_messages(channel_id, limit)
    click.echo(f"=== #{channel['name']} ===")
    if channel.get("description"):
        click.echo(f"  {channel['description']}")
    click.echo()
    if not messages:
        click.echo("  No messages yet.")
        return
    for msg in reversed(messages):
        name = msg.get("sender_name", msg["sender_fingerprint"][:12])
        ts = time.strftime("%H:%M", time.localtime(msg["timestamp"]))
        click.echo(f"  [{ts}] {name}: {msg['content']}")


# ═══════════════════════════════════════════════════════════════
# Status and peers
# ═══════════════════════════════════════════════════════════════

@cli.command("status")
def status():
    """Show MeshBox SANP node status."""
    # Try API first (daemon running = full status)
    if _daemon_running():
        st = _api_get("/api/v1/node/status")
        if st:
            click.echo("=== MeshBox SANP Node Status ===")
            click.echo(f"  Node:          {st.get('node_name', 'N/A')} ({st.get('fingerprint', 'N/A')})")
            click.echo(f"  Version:       {st.get('version', '?')}")
            click.echo(f"  Protocol:      SANP v{st.get('sanp_version', '?')}")
            click.echo(f"  SANP port:     {st.get('sanp_port', '?')}")
            click.echo(f"  API port:      {st.get('api_port', '?')}")
            click.echo(f"  Uptime:        {st.get('uptime', '?')}")
            click.echo(f"  Peers:         {st.get('connected_peers', 0)} connected")
            click.echo(f"  Routes:        {st.get('routes', 0)}")
            click.echo(f"  Messages:      {st.get('total_messages', 0)} total, {st.get('unread_messages', 0)} unread")
            click.echo(f"  Relay queue:   {st.get('relay_messages', 0)}")
            click.echo(f"  Contacts:      {st.get('total_profiles', 0)}")
            click.echo(f"  Files:         {st.get('total_files', 0)}")
            click.echo(f"  Channels:      {st.get('total_channels', 0)}")
            click.echo(f"  Active SOS:    {st.get('active_sos', 0)}")
            if st.get("onion_address"):
                click.echo(f"  Onion:         {st['onion_address']}")
            click.echo(f"  Tor:           {'Enabled' if st.get('tor_enabled') else 'Disabled'}")
            return

    # Offline fallback
    storage = get_components()
    p = storage.get_local_profile()
    if not p:
        click.echo("MeshBox not initialized.")
        click.echo("Run: meshbox start")
        sys.exit(1)

    stats = storage.get_stats()
    data_dir = get_data_dir()

    click.echo("=== MeshBox Status (offline) ===")
    click.echo(f"  Node:          {p['name']} ({p['fingerprint']})")
    click.echo(f"  Version:       {__version__}")
    click.echo(f"  Protocol:      SANP v1")
    click.echo(f"  Data dir:      {data_dir}")
    click.echo(f"  Messages:      {stats['total_messages']} total, {stats['unread_messages']} unread")
    click.echo(f"  Relay queue:   {stats['relay_messages']}")
    click.echo(f"  Contacts:      {stats['total_profiles']}")
    click.echo(f"  Files:         {stats['total_files']}")
    click.echo(f"  Channels:      {stats['total_channels']}")
    click.echo(f"  Active SOS:    {stats['active_sos']}")
    click.echo(f"  DB size:       {_format_size(stats['db_size_bytes'])}")
    click.echo()
    click.echo("  [SANP daemon not running - start with: meshbox start]")
    click.echo(f"  DB size:       {_format_size(stats['db_size_bytes'])}")

    # Tor status
    click.echo(f"  Tor peers:     {stats.get('tor_peers', 0)} ({stats.get('active_tor_peers', 0)} active)")
    click.echo(f"  Tor enabled:   {'Yes' if stats.get('tor_enabled') else 'No'}")

    # Check for onion address
    onion_file = data_dir / "onion_address"
    if onion_file.exists():
        click.echo(f"  Onion:         {onion_file.read_text().strip()}")


@cli.command("peers")
def list_peers():
    """Show connected SANP peers."""
    if _daemon_running():
        peers = _api_get("/api/v1/peers")
        if peers is not None:
            items = peers if isinstance(peers, list) else peers.get("peers", [])
            if not items:
                click.echo("No peers connected.")
                return
            click.echo(f"=== Connected Peers ({len(items)}) ===")
            for peer in items:
                name = peer.get("name") or peer.get("fingerprint", "?")[:12]
                addr = peer.get("address", "?")
                ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(peer.get("last_seen", 0)))
                click.echo(f"  {name} ({addr}) - last seen {ts}")
            return

    storage = get_components()
    peers = storage.get_recent_peers(20)
    if not peers:
        click.echo("No peers seen yet. Start the SANP node: meshbox start")
        return

    click.echo(f"=== Recent Peers ({len(peers)}) ===")
    for peer in peers:
        name = peer.get("peer_name") or peer["fingerprint"][:12]
        ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(peer["seen_at"]))
        conn = peer["connection_type"]
        click.echo(f"  {name} ({conn}) - last seen {ts}")


@cli.command("search")
@click.argument("query")
def search_messages(query):
    """Search messages by content, sender, or ID."""
    if _daemon_running():
        results = _api_get(f"/api/v1/messages/search/{query}")
        if results is not None:
            items = results if isinstance(results, list) else results.get("messages", [])
            if not items:
                click.echo(f"No messages matching '{query}'.")
                return
            click.echo(f"=== Search results ({len(items)}) ===")
            for msg in items:
                name = msg.get("sender_name", msg.get("sender_fingerprint", "?")[:12])
                ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(msg.get("timestamp", 0)))
                click.echo(f"  [{ts}] From: {name} - ID: {msg.get('message_id', '?')}")
            return

    storage = get_components()
    p = storage.get_local_profile()
    if not p:
        click.echo("No profile found.")
        sys.exit(1)

    results = storage.search_messages(p["fingerprint"], query)
    if not results:
        click.echo(f"No messages matching '{query}'.")
        return

    click.echo(f"=== Search results ({len(results)}) ===")
    for msg in results:
        name = msg.get("sender_name", msg["sender_fingerprint"][:12])
        ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(msg["timestamp"]))
        click.echo(f"  [{ts}] From: {name} - ID: {msg['message_id']}")


@cli.command("cleanup")
def cleanup():
    """Clean up expired messages and relay data."""
    storage = get_components()
    storage.cleanup_expired()
    click.echo("Expired messages cleaned up.")


# ═══════════════════════════════════════════════════════════════
# Daemon command
# ═══════════════════════════════════════════════════════════════

@cli.command("daemon")
@click.option("--log-level", "-l", type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]),
              default="INFO", help="Logging level")
def daemon_cmd(log_level):
    """[DEPRECATED] Start the legacy daemon.

    \b
    This command is deprecated. Use 'meshbox start' instead
    to launch the full SANP mesh node with Tor support.
    """
    click.echo("WARNING: 'meshbox daemon' is deprecated.")
    click.echo("Use 'meshbox start' to launch the SANP mesh node.")
    click.echo()
    click.echo("Redirecting to 'meshbox start'...")
    click.echo()
    import subprocess
    subprocess.call([sys.executable, "-m", "meshbox", "start", "--log-level", log_level])


# ═══════════════════════════════════════════════════════════════
# Web UI command
# ═══════════════════════════════════════════════════════════════

@cli.command("web")
@click.option("--host", "-h", default="127.0.0.1", help="Host to bind to")
@click.option("--port", "-p", default=8080, type=int, help="Port to listen on")
@click.option("--public", is_flag=True, help="Listen on all interfaces (0.0.0.0)")
def web_cmd(host, port, public):
    """Start the web UI.

    \b
    Opens a local web interface for managing MeshBox.
    By default, only accessible from localhost.
    Use --public to listen on all interfaces.
    """
    if public:
        host = "0.0.0.0"

    try:
        from meshbox.web import create_app
        app = create_app()
        click.echo(f"Starting MeshBox web UI on http://{host}:{port}")
        click.echo("Press Ctrl+C to stop.")
        app.run(host=host, port=port, debug=False)
    except ImportError:
        click.echo("Error: Flask is required for the web UI.")
        click.echo("Install with: pip install 'meshbox[web]'")
        sys.exit(1)


# ═══════════════════════════════════════════════════════════════
# Config command
# ═══════════════════════════════════════════════════════════════

@cli.command("verify")
@click.argument("fingerprint")
def verify_contact(fingerprint):
    """Verify a contact's identity with a safety number.

    \b
    Compare the safety number with your contact in person or
    over a trusted channel to confirm their identity.
    """
    storage = get_components()
    p = storage.get_local_profile()
    if not p:
        click.echo("No profile found.")
        sys.exit(1)

    contact = storage.get_profile(fingerprint)
    if not contact:
        click.echo(f"Unknown contact: {fingerprint}")
        sys.exit(1)

    # Compute safety number from both fingerprints
    import hashlib
    combined = "".join(sorted([p["fingerprint"], fingerprint]))
    safety_hash = hashlib.sha256(combined.encode()).hexdigest()
    safety_number = "".join(c for c in safety_hash if c.isdigit())[:20].ljust(20, "0")

    click.echo(f"=== Safety Number with {contact['name']} ===")
    click.echo()
    groups = [safety_number[i:i+5] for i in range(0, len(safety_number), 5)]
    for i in range(0, len(groups), 4):
        click.echo("  " + "  ".join(groups[i:i+4]))
    click.echo()
    click.echo("Compare this number with your contact in person.")
    click.echo("If the numbers match, the connection is verified.")


@cli.command("trust")
@click.argument("fingerprint")
def show_trust(fingerprint):
    """Show the trust score for a peer."""
    if _daemon_running():
        data = _api_get(f"/api/v1/trust/{fingerprint}")
        if data:
            name = data.get("name", fingerprint[:12])
            score = data.get("trust_score", 0)
            level = "HIGH" if score >= 0.7 else "MEDIUM" if score >= 0.4 else "LOW"
            click.echo(f"Trust for {name}: {score:.2f} ({level})")
            return

    storage = get_components()
    score = storage.get_trust_score(fingerprint)
    contact = storage.get_profile(fingerprint)
    name = contact["name"] if contact else fingerprint[:12]

    if score is None:
        click.echo(f"No trust data for {name}.")
        return

    level = "HIGH" if score >= 0.7 else "MEDIUM" if score >= 0.4 else "LOW"
    click.echo(f"Trust for {name}: {score:.2f} ({level})")


@cli.command("config")
def show_config():
    """Show MeshBox configuration and paths."""
    data_dir = get_data_dir()
    click.echo("=== MeshBox Configuration ===")
    click.echo(f"  Version:    {__version__}")
    click.echo(f"  Protocol:   SANP v1")
    click.echo(f"  Data dir:   {data_dir}")
    click.echo(f"  Database:   {data_dir / 'meshbox.db'}")
    click.echo(f"  Keys:       {data_dir / 'keys'}")
    click.echo(f"  Files:      {data_dir / 'files'}")
    click.echo(f"  Env var:    MESHBOX_DATA_DIR={os.environ.get('MESHBOX_DATA_DIR', '(not set)')}")


# ═══════════════════════════════════════════════════════════════
# Tor commands
# ═══════════════════════════════════════════════════════════════

@cli.group("tor")
def tor_group():
    """Manage Tor connectivity for internet-based P2P."""
    pass


@tor_group.command("enable")
def tor_enable():
    """Enable Tor connectivity."""
    storage = get_components()
    storage.set_setting("tor_enabled", "true")
    click.echo("Tor enabled. Restart the SANP node to apply.")


@tor_group.command("disable")
def tor_disable():
    """Disable Tor connectivity."""
    storage = get_components()
    storage.set_setting("tor_enabled", "false")
    click.echo("Tor disabled. Restart the SANP node to apply.")


@tor_group.command("status")
def tor_status():
    """Show Tor connectivity status."""
    storage = get_components()
    data_dir = get_data_dir()

    enabled = storage.get_setting("tor_enabled", "true") == "true"
    click.echo(f"  Tor enabled:  {'Yes' if enabled else 'No'}")

    onion_file = data_dir / "onion_address"
    if onion_file.exists():
        click.echo(f"  Onion addr:   {onion_file.read_text().strip()}")
    else:
        click.echo("  Onion addr:   (not yet generated - start daemon)")

    tor_peers = storage.get_all_tor_peers()
    active = storage.get_active_tor_peers()
    directory = storage.get_directory_nodes()

    click.echo(f"  Total peers:  {len(tor_peers)}")
    click.echo(f"  Active peers: {len(active)}")
    click.echo(f"  Dir. nodes:   {len(directory)}")


@tor_group.command("peers")
@click.option("--active", "-a", is_flag=True, help="Show only active peers")
def tor_peers(active):
    """List known Tor peers."""
    storage = get_components()

    if active:
        peers = storage.get_active_tor_peers()
    else:
        peers = storage.get_all_tor_peers()

    if not peers:
        click.echo("No Tor peers known.")
        return

    click.echo(f"=== Tor Peers ({len(peers)}) ===")
    for p in peers:
        name = p.get("name") or p["fingerprint"][:12]
        onion = p["onion_address"][:24] + "..."
        ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(p["last_seen"]))
        dir_flag = " [DIR]" if p.get("is_directory_node") else ""
        click.echo(f"  {name} ({onion}){dir_flag} - last seen {ts}")


@tor_group.command("add-peer")
@click.argument("onion_address")
@click.option("--name", "-n", default="", help="Optional name for the peer")
def tor_add_peer(onion_address, name):
    """Add a Tor peer manually by onion address."""
    storage = get_components()

    if not onion_address.endswith(".onion"):
        click.echo("Error: Must be a .onion address")
        sys.exit(1)

    fp = onion_address.replace(".onion", "")[:16]
    storage.save_tor_peer({
        "fingerprint": fp,
        "onion_address": onion_address,
        "name": name,
    })
    click.echo(f"Tor peer added: {onion_address}")


@tor_group.command("directory-enable")
def tor_directory_enable():
    """Enable directory node mode (serve as a directory for the network)."""
    storage = get_components()
    storage.set_setting("directory_node_enabled", "true")
    click.echo("Directory node mode enabled. Restart the SANP node to apply.")
    click.echo("This node will now serve as a directory node for the MeshBox network.")


@tor_group.command("directory-disable")
def tor_directory_disable():
    """Disable directory node mode."""
    storage = get_components()
    storage.set_setting("directory_node_enabled", "false")
    click.echo("Directory node mode disabled. Restart the SANP node to apply.")


@tor_group.command("directory-status")
def tor_directory_status():
    """Show directory node status."""
    storage = get_components()

    dir_enabled = storage.get_setting("directory_node_enabled", "false") == "true"
    click.echo(f"  Directory node: {'Enabled' if dir_enabled else 'Disabled'}")

    announced = storage.get_announced_peers_count()
    click.echo(f"  Peers registered: {announced}")

    directory_nodes = storage.get_directory_nodes()
    click.echo(f"  Known directory nodes: {len(directory_nodes)}")

    if directory_nodes:
        click.echo()
        click.echo("  === Known Directory Nodes ===")
        for node in directory_nodes:
            name = node.get("name") or node["fingerprint"][:12]
            onion = node["onion_address"][:24] + "..."
            click.echo(f"    {name} ({onion})")


# ═══════════════════════════════════════════════════════════════
# SANP mesh daemon command
# ═══════════════════════════════════════════════════════════════

@cli.command("start")
@click.option("--port", "-p", default=7777, type=int, help="SANP protocol port (default: 7777)")
@click.option("--api-port", default=8080, type=int, help="REST API port (default: 8080)")
@click.option("--data-dir", "-d", default="~/.meshbox", help="Data directory")
@click.option("--seeds", "-s", default="", help="Comma-separated seed addresses (host.onion:port)")
@click.option("--passphrase", envvar="MESHBOX_PASSPHRASE", default="", help="Identity encryption passphrase")
@click.option("--log-level", "-l", type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]),
              default="INFO", help="Logging level")
@click.option("--verbose", "-v", is_flag=True, help="Enable debug logging")
def start_sanp(port, api_port, data_dir, seeds, passphrase, log_level, verbose):
    """Start the SANP mesh network daemon.

    \b
    This launches the full Tor-based mesh node:
      - Ed25519/X25519 cryptographic identity
      - Tor hidden service (.onion)
      - SANP protocol server (port 7777)
      - REST API (port 8080)
      - DHT discovery + gossip protocol
      - Automatic peer bootstrap

    \b
    Examples:
      meshbox start
      meshbox start --port 7777 --api-port 8080
      meshbox start --seeds "abc.onion:7777,def.onion:7777"
      meshbox start -v  # verbose/debug mode
    """
    import asyncio
    import logging

    level = logging.DEBUG if verbose else getattr(logging, log_level)
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    seed_list = [s.strip() for s in seeds.split(",") if s.strip()] if seeds else None

    from meshbox.main import _run_daemon

    click.echo("╔══════════════════════════════════════════╗")
    click.echo("║       MESHBOX SANP NODE v5.0             ║")
    click.echo("╚══════════════════════════════════════════╝")
    click.echo(f"  Data dir:   {data_dir}")
    click.echo(f"  SANP port:  {port}")
    click.echo(f"  API port:   {api_port}")
    if seed_list:
        click.echo(f"  Seeds:      {', '.join(seed_list)}")
    click.echo()
    click.echo("Press Ctrl+C to stop.")
    click.echo()

    try:
        asyncio.run(_run_daemon(
            data_dir=data_dir,
            sanp_port=port,
            api_port=api_port,
            passphrase=passphrase,
            seeds=seed_list,
        ))
    except KeyboardInterrupt:
        click.echo("\nNode stopped.")


# ═══════════════════════════════════════════════════════════════
# Update commands
# ═══════════════════════════════════════════════════════════════

@cli.command("update")
@click.option("--check", "check_only", is_flag=True, help="Just check, don't download")
def update_cmd(check_only):
    """Check for MeshBox updates."""
    import asyncio
    from meshbox.updater import UpdateChecker

    storage = get_components()
    checker = UpdateChecker(storage=storage)

    click.echo(f"Current version: {checker.current_version}")
    click.echo("Checking for updates...")

    result = asyncio.run(checker.check_for_updates(force=True))

    if result:
        click.echo(f"Update available: {result.get('version', '?')}")
        if result.get("changelog"):
            click.echo(f"Changelog: {result['changelog']}")
        if result.get("download_url") and not check_only:
            click.echo(f"Download: {result['download_url']}")
    else:
        click.echo("You are running the latest version.")


# ═══════════════════════════════════════════════════════════════
# Settings commands
# ═══════════════════════════════════════════════════════════════

@cli.command("settings")
@click.option("--set", "-s", "key_value", nargs=2, help="Set a setting: KEY VALUE")
@click.option("--get", "-g", "get_key", help="Get a specific setting")
def settings_cmd(key_value, get_key):
    """View or update node settings."""
    storage = get_components()

    if key_value:
        key, value = key_value
        storage.set_setting(key, value)
        click.echo(f"Setting '{key}' = '{value}'")
    elif get_key:
        value = storage.get_setting(get_key)
        click.echo(f"{get_key} = {value}" if value else f"{get_key} is not set")
    else:
        settings = storage.get_all_settings()
        if not settings:
            click.echo("No settings configured.")
            return
        click.echo("=== Node Settings ===")
        for k, v in sorted(settings.items()):
            click.echo(f"  {k} = {v}")


# ═══════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════

def _format_size(size_bytes: int) -> str:
    if size_bytes < 1024:
        return f"{size_bytes} B"
    if size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    return f"{size_bytes / (1024 * 1024):.1f} MB"


def main():
    cli()


if __name__ == "__main__":
    main()
