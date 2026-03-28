"""
MeshBox CLI - Modern command-line interface for decentralized encrypted communication.
"""

import json
import os
import sys
import time
import uuid
from pathlib import Path

import click

from meshbox import __version__
from meshbox.config import DATA_DIR
from meshbox.crypto import Identity, CryptoEngine
from meshbox.files import FileManager
from meshbox.profiles import ProfileManager
from meshbox.storage import StorageEngine


def get_data_dir() -> Path:
    """Get and ensure the data directory exists."""
    data_dir = DATA_DIR
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


def get_components():
    """Initialize core components."""
    data_dir = get_data_dir()
    storage = StorageEngine(data_dir / "meshbox.db")
    profile_mgr = ProfileManager(storage, data_dir / "keys")
    return storage, profile_mgr


# ═══════════════════════════════════════════════════════════════
# Main CLI group
# ═══════════════════════════════════════════════════════════════

@click.group()
@click.version_option(version=__version__, prog_name="MeshBox")
def cli():
    """MeshBox - Decentralized encrypted mesh communication.

    \b
    Secure, offline-first messaging over WiFi and Bluetooth mesh networks.
    Data is stored in ~/.meshbox/ (override with MESHBOX_DATA_DIR env var).

    \b
    Quick start:
      meshbox profile create --name "Alice"
      meshbox send --to <fingerprint> --message "Hello!"
      meshbox inbox
      meshbox daemon
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
    storage, profile_mgr = get_components()

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
    click.echo("Share your fingerprint so others can send you messages.")
    click.echo("Start the network daemon with: meshbox daemon")


@profile.command("show")
def profile_show():
    """Display the local profile."""
    storage, profile_mgr = get_components()

    p = profile_mgr.get_local_profile()
    if not p:
        click.echo("No profile found. Create one with: meshbox profile create --name 'Your Name'")
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
    storage, profile_mgr = get_components()

    if not profile_mgr.is_initialized:
        click.echo("No profile found. Create one first.")
        sys.exit(1)

    data = profile_mgr.export_profile_for_sharing()

    if fmt == "json":
        click.echo(json.dumps(data, indent=2))
    elif fmt == "qr":
        try:
            import qrcode
            qr = qrcode.QRCode(version=1, box_size=1, border=1)
            qr.add_data(json.dumps(data))
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
    storage, profile_mgr = get_components()
    if not profile_mgr.is_initialized:
        click.echo("No profile found.")
        sys.exit(1)
    profile_mgr.update_profile(name=name, bio=bio)
    click.echo("Profile updated.")


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

    storage = StorageEngine(data_dir / "meshbox.db")
    local = storage.get_local_profile()
    if local:
        # Remove from profiles table
        with storage._transaction() as conn:
            conn.execute("DELETE FROM profiles WHERE is_local = 1")

    click.echo("Profile and keys deleted.")


# ═══════════════════════════════════════════════════════════════
# Messaging commands
# ═══════════════════════════════════════════════════════════════

@cli.command("send")
@click.option("--to", "-t", "recipient", required=True, help="Recipient fingerprint")
@click.option("--message", "-m", "text", required=True, help="Message text")
def send_message(recipient, text):
    """Send an encrypted message."""
    storage, profile_mgr = get_components()

    if not profile_mgr.is_initialized:
        click.echo("No profile found. Create one first.")
        sys.exit(1)

    contact = storage.get_profile(recipient)
    if not contact:
        click.echo(f"Unknown recipient: {recipient}")
        click.echo("The recipient must be in your contacts (discovered on the network).")
        sys.exit(1)

    crypto = CryptoEngine(profile_mgr.identity)
    encrypted = crypto.encrypt_message(text, contact["box_public_key"])

    message = {
        "message_id": str(uuid.uuid4()),
        "sender_fingerprint": profile_mgr.identity.fingerprint,
        "recipient_fingerprint": recipient,
        "encrypted_payload": encrypted,
        "timestamp": int(time.time()),
        "ttl": 604800,
        "hop_count": 0,
        "delivered": 0,
        "proof_of_work": 0,
    }

    storage.save_message(message)
    storage.save_relay_message(message)

    click.echo("Message encrypted and queued.")
    click.echo(f"  ID:        {message['message_id']}")
    click.echo(f"  To:        {contact['name']} ({recipient})")
    click.echo(f"  Expires:   7 days")
    click.echo()
    click.echo("The message will be delivered via the mesh network.")


@cli.command("inbox")
@click.option("--unread", "-u", is_flag=True, help="Show only unread messages")
def inbox(unread):
    """Show received messages."""
    storage, profile_mgr = get_components()

    if not profile_mgr.is_initialized:
        click.echo("No profile found.")
        sys.exit(1)

    messages = storage.get_inbox(profile_mgr.identity.fingerprint)
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
    storage, profile_mgr = get_components()

    if not profile_mgr.is_initialized:
        click.echo("No profile found.")
        sys.exit(1)

    messages = storage.get_outbox(profile_mgr.identity.fingerprint)
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
    """Read and decrypt a message."""
    storage, profile_mgr = get_components()

    if not profile_mgr.is_initialized:
        click.echo("No profile found.")
        sys.exit(1)

    inbox = storage.get_inbox(profile_mgr.identity.fingerprint)
    target = None
    for msg in inbox:
        if msg["message_id"] == message_id:
            target = msg
            break

    if not target:
        click.echo("Message not found.")
        sys.exit(1)

    crypto = CryptoEngine(profile_mgr.identity)
    payload = json.loads(target["encrypted_payload"]) \
        if isinstance(target["encrypted_payload"], str) else target["encrypted_payload"]
    plaintext = crypto.decrypt_message(payload)

    sender = storage.get_profile(target["sender_fingerprint"])
    sender_name = sender["name"] if sender else target["sender_fingerprint"]
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(target["timestamp"]))

    click.echo(f"=== Message from {sender_name} ===")
    click.echo(f"Date:  {ts}")
    click.echo(f"ID:    {message_id}")
    click.echo("---")
    if plaintext:
        click.echo(plaintext)
    else:
        click.echo("[ERROR: Unable to decrypt message]")

    storage.mark_read(message_id)


@cli.command("delete")
@click.argument("message_id")
def delete_message(message_id):
    """Delete a message by ID."""
    storage, _ = get_components()
    storage.delete_message(message_id)
    click.echo(f"Message {message_id} deleted.")


# ═══════════════════════════════════════════════════════════════
# Contact commands
# ═══════════════════════════════════════════════════════════════

@cli.command("contacts")
def list_contacts():
    """List known contacts."""
    storage, profile_mgr = get_components()

    contacts = profile_mgr.get_all_contacts()
    if not contacts:
        click.echo("No contacts. Start the daemon to discover peers.")
        return

    click.echo(f"=== Contacts ({len(contacts)}) ===")
    for c in contacts:
        last = time.strftime("%Y-%m-%d %H:%M", time.localtime(c["last_seen"]))
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
    storage, profile_mgr = get_components()

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

    profile_mgr.add_contact_from_discovery(data)
    click.echo(f"Contact added: {data['name']} ({data['fingerprint']})")


@cli.command("remove-contact")
@click.argument("fingerprint")
def remove_contact(fingerprint):
    """Remove a contact by fingerprint."""
    storage, _ = get_components()
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
    """Share an encrypted file over the mesh network."""
    storage, profile_mgr = get_components()

    if not profile_mgr.is_initialized:
        click.echo("No profile found.")
        sys.exit(1)

    data_dir = get_data_dir()
    file_mgr = FileManager(storage, profile_mgr.identity, data_dir / "files")

    with open(filepath, "rb") as f:
        file_data = f.read()

    filename = os.path.basename(filepath)
    try:
        result = file_mgr.share_file(
            file_data=file_data,
            filename=filename,
            recipient_fingerprint=recipient,
            description=desc,
            is_public=public,
        )
        size_str = FileManager.format_file_size(len(file_data))
        click.echo(f"File shared: {filename} ({size_str})")
        click.echo(f"  ID: {result['file_id']}")
        if public:
            click.echo("  Mode: PUBLIC")
        elif recipient:
            click.echo(f"  To: {recipient}")
    except ValueError as e:
        click.echo(f"Error: {e}")
        sys.exit(1)


@cli.command("files")
def list_files():
    """List shared files."""
    storage, profile_mgr = get_components()

    if not profile_mgr.is_initialized:
        click.echo("No profile found.")
        sys.exit(1)

    data_dir = get_data_dir()
    file_mgr = FileManager(storage, profile_mgr.identity, data_dir / "files")

    my_files = file_mgr.get_my_files()
    received = file_mgr.get_received_files()

    click.echo(f"=== Shared files ({len(my_files)}) ===")
    for f in my_files:
        size = FileManager.format_file_size(f["file_size"])
        click.echo(f"  [{f['file_id'][:8]}] {f['filename']} ({size})")

    click.echo(f"\n=== Received files ({len(received)}) ===")
    for f in received:
        size = FileManager.format_file_size(f["file_size"])
        sender = f.get("sender_name", f["sender_fingerprint"][:12])
        click.echo(f"  [{f['file_id'][:8]}] {f['filename']} ({size}) from {sender}")


# ═══════════════════════════════════════════════════════════════
# SOS commands
# ═══════════════════════════════════════════════════════════════

@cli.command("sos")
@click.argument("message")
@click.option("--severity", "-s", type=click.Choice(["low", "high", "critical"]), default="high",
              help="Alert severity level")
def sos_alert(message, severity):
    """Broadcast an SOS alert over the mesh network."""
    storage, profile_mgr = get_components()

    if not profile_mgr.is_initialized:
        click.echo("No profile found.")
        sys.exit(1)

    alert = {
        "alert_id": str(uuid.uuid4()),
        "sender_fingerprint": profile_mgr.identity.fingerprint,
        "message": message,
        "severity": severity,
        "timestamp": int(time.time()),
        "ttl": 86400,
    }
    storage.save_sos_alert(alert)

    click.echo("SOS ALERT BROADCAST")
    click.echo(f"  Severity: {severity.upper()}")
    click.echo(f"  Message:  {message}")
    click.echo(f"  ID:       {alert['alert_id'][:8]}")


@cli.command("sos-list")
def sos_list():
    """List active SOS alerts."""
    storage, _ = get_components()
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
    storage, _ = get_components()
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
    storage, profile_mgr = get_components()

    if not profile_mgr.is_initialized:
        click.echo("No profile found.")
        sys.exit(1)

    channel = {
        "channel_id": str(uuid.uuid4()),
        "name": name,
        "description": desc,
        "creator_fingerprint": profile_mgr.identity.fingerprint,
        "is_public": 1,
    }
    storage.create_channel(channel)
    click.echo(f"Channel '#{name}' created (ID: {channel['channel_id'][:8]})")


@channel_group.command("post")
@click.argument("channel_id")
@click.option("--message", "-m", required=True, help="Message content")
def channel_post(channel_id, message):
    """Post a message to a channel."""
    storage, profile_mgr = get_components()

    if not profile_mgr.is_initialized:
        click.echo("No profile found.")
        sys.exit(1)

    channel = storage.get_channel(channel_id)
    if not channel:
        click.echo("Channel not found.")
        sys.exit(1)

    storage.post_channel_message({
        "message_id": str(uuid.uuid4()),
        "channel_id": channel_id,
        "sender_fingerprint": profile_mgr.identity.fingerprint,
        "content": message,
    })
    click.echo(f"Posted to #{channel['name']}")


@channel_group.command("view")
@click.argument("channel_id")
@click.option("--limit", "-l", default=20, help="Number of messages to show")
def channel_view(channel_id, limit):
    """View messages in a channel."""
    storage, _ = get_components()

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
    """Show MeshBox node status."""
    storage, profile_mgr = get_components()

    p = profile_mgr.get_local_profile()
    if not p:
        click.echo("MeshBox not initialized.")
        click.echo("Run: meshbox profile create --name 'Your Name'")
        sys.exit(1)

    stats = storage.get_stats()
    data_dir = get_data_dir()

    click.echo("=== MeshBox Status ===")
    click.echo(f"  Node:          {p['name']} ({p['fingerprint']})")
    click.echo(f"  Data dir:      {data_dir}")
    click.echo(f"  Messages:      {stats['total_messages']} total, {stats['unread_messages']} unread")
    click.echo(f"  Relay queue:   {stats['relay_messages']}")
    click.echo(f"  Contacts:      {stats['total_profiles']}")
    click.echo(f"  Peers seen:    {stats['total_peers_seen']}")
    click.echo(f"  Files:         {stats['total_files']}")
    click.echo(f"  Channels:      {stats['total_channels']}")
    click.echo(f"  Active SOS:    {stats['active_sos']}")
    click.echo(f"  DB size:       {_format_size(stats['db_size_bytes'])}")


@cli.command("peers")
def list_peers():
    """Show recently seen peers."""
    storage, _ = get_components()
    peers = storage.get_recent_peers(20)

    if not peers:
        click.echo("No peers seen yet. Start the daemon to discover peers.")
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
    """Search messages by sender name, ID, or fingerprint."""
    storage, profile_mgr = get_components()

    if not profile_mgr.is_initialized:
        click.echo("No profile found.")
        sys.exit(1)

    results = storage.search_messages(profile_mgr.identity.fingerprint, query)

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
    storage, _ = get_components()
    storage.cleanup_expired()
    click.echo("Expired messages cleaned up.")


# ═══════════════════════════════════════════════════════════════
# Daemon command
# ═══════════════════════════════════════════════════════════════

@cli.command("daemon")
@click.option("--log-level", "-l", type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]),
              default="INFO", help="Logging level")
def daemon_cmd(log_level):
    """Start the mesh network daemon.

    \b
    This starts the background services:
    - WiFi peer discovery (UDP broadcast)
    - Bluetooth LE scanning
    - TCP message transport
    - Periodic sync and cleanup
    """
    import logging
    from meshbox.daemon import MeshBoxDaemon

    data_dir = get_data_dir()

    logging.basicConfig(
        level=getattr(logging, log_level),
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    daemon = MeshBoxDaemon(data_dir)

    if not daemon.is_initialized:
        click.echo("Error: Profile not initialized.")
        click.echo("Run first: meshbox profile create --name 'Your Name'")
        sys.exit(1)

    click.echo(f"Starting MeshBox daemon (data: {data_dir})...")
    click.echo("Press Ctrl+C to stop.")

    import asyncio
    try:
        asyncio.run(daemon.start())
    except KeyboardInterrupt:
        click.echo("\nDaemon stopped.")


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

@cli.command("config")
def show_config():
    """Show MeshBox configuration and paths."""
    data_dir = get_data_dir()
    click.echo("=== MeshBox Configuration ===")
    click.echo(f"  Version:    {__version__}")
    click.echo(f"  Data dir:   {data_dir}")
    click.echo(f"  Database:   {data_dir / 'meshbox.db'}")
    click.echo(f"  Keys:       {data_dir / 'keys'}")
    click.echo(f"  Files:      {data_dir / 'files'}")
    click.echo(f"  Env var:    MESHBOX_DATA_DIR={os.environ.get('MESHBOX_DATA_DIR', '(not set)')}")


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
