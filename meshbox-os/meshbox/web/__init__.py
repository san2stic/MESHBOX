"""
MeshBox - Web UI (optional).
Local Flask server for managing MeshBox via a browser.
"""

import hashlib
import json
import os
import time
import uuid
from io import BytesIO
from pathlib import Path

from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    redirect,
    url_for,
    flash,
    session,
    send_file,
)

from meshbox.config import DATA_DIR
from meshbox.crypto import Identity, CryptoEngine
from meshbox.files import FileManager
from meshbox.profiles import ProfileManager
from meshbox.storage import StorageEngine


def create_app(data_dir: Path = None) -> Flask:
    """Create and configure the Flask application."""
    data_dir = data_dir or DATA_DIR
    data_dir.mkdir(parents=True, exist_ok=True)

    app = Flask(
        __name__,
        template_folder=str(Path(__file__).parent / "templates"),
        static_folder=str(Path(__file__).parent / "static"),
    )
    app.secret_key = os.environ.get(
        "MESHBOX_SECRET_KEY",
        hashlib.sha256(str(data_dir).encode()).hexdigest(),
    )

    # Components stored in app config
    storage = StorageEngine(data_dir / "meshbox.db")
    profile_mgr = ProfileManager(storage, data_dir / "keys")
    file_mgr = None
    if profile_mgr.is_initialized:
        file_mgr = FileManager(storage, profile_mgr.identity, data_dir / "files")

    app.config["_storage"] = storage
    app.config["_profile_mgr"] = profile_mgr
    app.config["_file_mgr"] = file_mgr
    app.config["_data_dir"] = data_dir

    SETUP_FLAG = data_dir / ".setup_complete"

    # === Helpers ===

    def _time_ago(timestamp: int) -> str:
        diff = int(time.time()) - timestamp
        if diff < 60:
            return "just now"
        if diff < 3600:
            m = diff // 60
            return f"{m}m ago"
        if diff < 86400:
            h = diff // 3600
            return f"{h}h ago"
        d = diff // 86400
        if d == 1:
            return "yesterday"
        if d < 30:
            return f"{d}d ago"
        return time.strftime("%Y-%m-%d", time.localtime(timestamp))

    def _format_size(size_bytes: int) -> str:
        if size_bytes < 1024:
            return f"{size_bytes} B"
        if size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        return f"{size_bytes / (1024 * 1024):.1f} MB"

    def _get_unread_count() -> int:
        if not profile_mgr.is_initialized:
            return 0
        stats = storage.get_stats()
        return stats.get("unread_messages", 0)

    def _get_active_sos_count() -> int:
        stats = storage.get_stats()
        return stats.get("active_sos", 0)

    def _needs_setup():
        if SETUP_FLAG.exists():
            return False
        if profile_mgr.is_initialized:
            return False
        return True

    # === Context Processor ===

    @app.context_processor
    def inject_globals():
        p = profile_mgr.get_local_profile() if profile_mgr.is_initialized else None
        return {
            "profile": p,
            "unread_count": _get_unread_count(),
            "sos_count": _get_active_sos_count(),
        }

    # === Before Request ===

    @app.before_request
    def before_request():
        nonlocal file_mgr
        if file_mgr is None and profile_mgr.is_initialized:
            file_mgr = FileManager(storage, profile_mgr.identity, data_dir / "files")
            app.config["_file_mgr"] = file_mgr
        if _needs_setup() and request.endpoint not in ('setup', 'static'):
            return redirect(url_for('setup'))

    # === Routes: Setup ===

    @app.route("/setup", methods=["GET", "POST"])
    def setup():
        if not _needs_setup():
            return redirect(url_for("dashboard"))

        if request.method == "POST":
            data = request.get_json()
            if not data:
                return jsonify({"success": False, "error": "Missing data"}), 400

            name = (data.get("name") or "").strip()
            bio = (data.get("bio") or "").strip()
            password = data.get("password", "")
            has_password = data.get("hasPassword", False)

            if not name or len(name) < 3 or len(name) > 32:
                return jsonify({"success": False, "error": "Invalid name (3-32 chars)"}), 400

            try:
                profile_mgr.create_profile(name, bio)
                profile = profile_mgr.get_local_profile()

                if has_password and password and len(password) >= 6:
                    pw_hash = hashlib.sha256(password.encode()).hexdigest()
                    pw_file = data_dir / ".web_password"
                    pw_file.write_text(pw_hash)
                    try:
                        pw_file.chmod(0o600)
                    except OSError:
                        pass

                SETUP_FLAG.touch()

                return jsonify({
                    "success": True,
                    "name": name,
                    "fingerprint": profile.get("fingerprint", ""),
                })
            except Exception as e:
                return jsonify({"success": False, "error": str(e)}), 500

        return render_template("setup.html")

    # === Routes: Dashboard ===

    @app.route("/")
    def dashboard():
        stats = storage.get_stats()
        p = profile_mgr.get_local_profile()
        recent_messages = []
        if p:
            inbox_msgs = storage.get_inbox(p["fingerprint"])
            for msg in inbox_msgs[:5]:
                sender = storage.get_profile(msg["sender_fingerprint"])
                msg["sender_name"] = sender["name"] if sender else msg["sender_fingerprint"][:12]
                msg["time_ago"] = _time_ago(msg["timestamp"])
                recent_messages.append(msg)

        recent_peers = storage.get_recent_peers(8)
        for peer in recent_peers:
            peer["time_ago"] = _time_ago(peer["seen_at"])

        return render_template(
            "dashboard.html", title="Dashboard", active="dashboard",
            stats=stats, recent_messages=recent_messages, recent_peers=recent_peers,
        )

    # === Routes: Inbox ===

    @app.route("/inbox")
    def inbox():
        p = profile_mgr.get_local_profile()
        if not p:
            return redirect(url_for("profile_page"))

        messages = storage.get_inbox(p["fingerprint"])
        for msg in messages:
            sender = storage.get_profile(msg["sender_fingerprint"])
            msg["sender_name"] = sender["name"] if sender else msg["sender_fingerprint"][:12]
            msg["time"] = time.strftime("%d/%m/%Y %H:%M", time.localtime(msg["timestamp"]))

        return render_template("inbox.html", title="Messages", active="inbox", messages=messages)

    # === Routes: Outbox ===

    @app.route("/outbox")
    def outbox():
        p = profile_mgr.get_local_profile()
        if not p:
            return redirect(url_for("profile_page"))

        messages = storage.get_outbox(p["fingerprint"])
        for msg in messages:
            recipient = storage.get_profile(msg["recipient_fingerprint"])
            msg["recipient_name"] = (
                recipient["name"] if recipient else msg["recipient_fingerprint"][:12]
            )
            msg["time"] = time.strftime("%d/%m/%Y %H:%M", time.localtime(msg["timestamp"]))

        return render_template("outbox.html", title="Sent", active="outbox", messages=messages)

    # === Routes: Read Message ===

    @app.route("/read/<message_id>")
    def read_msg(message_id):
        p = profile_mgr.get_local_profile()
        if not p:
            return redirect(url_for("profile_page"))

        target = storage.get_message_by_id(message_id)
        if not target:
            return redirect(url_for("inbox"))

        crypto = CryptoEngine(profile_mgr.identity)
        payload = (
            json.loads(target["encrypted_payload"])
            if isinstance(target["encrypted_payload"], str)
            else target["encrypted_payload"]
        )
        plaintext = crypto.decrypt_message(payload)
        storage.mark_read(message_id)

        sender = storage.get_profile(target["sender_fingerprint"])
        sender_name = sender["name"] if sender else target["sender_fingerprint"][:12]

        return render_template(
            "read.html", title="Message", active="inbox",
            sender_name=sender_name, sender_fingerprint=target["sender_fingerprint"],
            msg_time=time.strftime("%d/%m/%Y %H:%M:%S", time.localtime(target["timestamp"])),
            plaintext=plaintext, message_id=message_id,
        )

    @app.route("/delete-message/<message_id>", methods=["POST"])
    def delete_message_route(message_id):
        storage.delete_message(message_id)
        return redirect(url_for("inbox"))

    # === Routes: Send ===

    @app.route("/send", methods=["GET", "POST"])
    def send():
        p = profile_mgr.get_local_profile()
        if not p:
            return redirect(url_for("profile_page"))

        contacts = profile_mgr.get_all_contacts()
        selected_to = request.args.get("to", "")
        alert = None
        alert_type = None

        if request.method == "POST":
            recipient = request.form.get("to", "").strip()
            message_text = request.form.get("message", "").strip()

            if not recipient or not message_text:
                alert = "Recipient and message required."
                alert_type = "error"
            else:
                contact = storage.get_profile(recipient)
                if not contact:
                    alert = "Unknown recipient."
                    alert_type = "error"
                else:
                    crypto = CryptoEngine(profile_mgr.identity)
                    encrypted = crypto.encrypt_message(message_text, contact["box_public_key"])

                    msg = {
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
                    storage.save_message(msg)
                    storage.save_relay_message(msg)

                    alert = f"Encrypted message sent to {contact['name']}!"
                    alert_type = "success"

        return render_template(
            "send.html", title="Compose", active="send",
            contacts=contacts, selected_to=selected_to,
            alert=alert, alert_type=alert_type,
        )

    # === Routes: Contacts ===

    @app.route("/contacts")
    def contacts_page():
        contacts = profile_mgr.get_all_contacts()
        for c in contacts:
            c["last_seen_str"] = time.strftime(
                "%d/%m/%Y %H:%M", time.localtime(c["last_seen"])
            )
        return render_template("contacts.html", title="Contacts", active="contacts", contacts=contacts)

    @app.route("/add-contact", methods=["POST"])
    def add_contact():
        json_data = request.form.get("json_data", "")
        try:
            data = json.loads(json_data)
            required = ["fingerprint", "name", "verify_key", "box_public_key"]
            for field in required:
                if field not in data:
                    return redirect(url_for("contacts_page"))
            profile_mgr.add_contact_from_discovery(data)
        except (json.JSONDecodeError, KeyError):
            pass
        return redirect(url_for("contacts_page"))

    @app.route("/delete-contact/<fingerprint>", methods=["POST"])
    def delete_contact(fingerprint):
        storage.delete_contact(fingerprint)
        return redirect(url_for("contacts_page"))

    # === Routes: Profile ===

    @app.route("/profile")
    def profile_page():
        p = profile_mgr.get_local_profile()
        public_json = ""
        created_str = ""
        if p:
            public_data = profile_mgr.export_profile_for_sharing()
            public_json = json.dumps(public_data, indent=2)
            created_str = time.strftime("%d/%m/%Y %H:%M", time.localtime(p["created_at"]))
        return render_template(
            "profile.html", title="Profile & Keys", active="profile",
            public_json=public_json, created_str=created_str,
        )

    @app.route("/profile/create", methods=["POST"])
    def profile_create():
        name = request.form.get("name", "").strip()
        bio = request.form.get("bio", "").strip()
        if not name:
            return redirect(url_for("profile_page"))
        profile_mgr.create_profile(name, bio)
        return redirect(url_for("profile_page"))

    @app.route("/profile/update", methods=["POST"])
    def profile_update():
        name = request.form.get("name", "").strip()
        bio = request.form.get("bio", "").strip()
        profile_mgr.update_profile(name=name or None, bio=bio)
        return redirect(url_for("profile_page"))

    # === Routes: Network ===

    @app.route("/network")
    def network_page():
        stats = storage.get_stats()
        peers = storage.get_recent_peers(50)
        for peer in peers:
            peer["time_ago"] = _time_ago(peer["seen_at"])
        contacts_list = profile_mgr.get_all_contacts()
        recent_fps = {peer["fingerprint"] for peer in peers[:10]}
        return render_template(
            "network.html", title="Network", active="network",
            stats=stats, peers=peers, contacts_list=contacts_list, recent_fps=recent_fps,
        )

    # === Routes: Settings ===

    @app.route("/settings")
    def settings_page():
        stats = storage.get_stats()
        db_size = _format_size(stats.get("db_size_bytes", 0))
        return render_template(
            "settings.html", title="Settings", active="settings",
            stats=stats, db_size=db_size,
        )

    @app.route("/settings/cleanup", methods=["POST"])
    def settings_cleanup():
        storage.cleanup_expired()
        return redirect(url_for("settings_page"))

    # === Routes: Files ===

    @app.route("/files")
    def files_page():
        p = profile_mgr.get_local_profile()
        if not p:
            return redirect(url_for("profile_page"))

        fm = app.config.get("_file_mgr")
        my_files = fm.get_my_files() if fm else []
        received_files = fm.get_received_files() if fm else []
        public_files = fm.get_public_files() if fm else []

        for f in my_files + received_files + public_files:
            f["size_str"] = FileManager.format_file_size(f["file_size"])
            f["icon"] = FileManager.get_file_icon(f.get("mime_type", ""))
            f["time_ago"] = _time_ago(f["timestamp"])

        contacts = profile_mgr.get_all_contacts()
        return render_template(
            "files.html", title="Files", active="files",
            my_files=my_files, received_files=received_files,
            public_files=public_files, contacts=contacts,
        )

    @app.route("/files/upload", methods=["POST"])
    def files_upload():
        p = profile_mgr.get_local_profile()
        fm = app.config.get("_file_mgr")
        if not p or not fm:
            return redirect(url_for("files_page"))

        uploaded = request.files.get("file")
        if not uploaded or not uploaded.filename:
            flash("No file selected.", "error")
            return redirect(url_for("files_page"))

        recipient = request.form.get("recipient", "").strip()
        description = request.form.get("description", "").strip()
        is_public = request.form.get("is_public") == "on"

        if not is_public and not recipient:
            flash("Please select a recipient or mark the file as public.", "error")
            return redirect(url_for("files_page"))

        file_data = uploaded.read()
        if len(file_data) > 10 * 1024 * 1024:
            flash("File too large (max 10 MB).", "error")
            return redirect(url_for("files_page"))

        try:
            import base64
            file_meta = fm.share_file(
                file_data=file_data, filename=uploaded.filename,
                recipient_fingerprint=recipient if not is_public else "",
                description=description, is_public=is_public,
            )

            relay_msg = {
                "message_id": file_meta["file_id"],
                "sender_fingerprint": p["fingerprint"],
                "recipient_fingerprint": recipient if not is_public else "__PUBLIC__",
                "encrypted_payload": {
                    "type": "file",
                    "file_id": file_meta["file_id"],
                    "filename": file_meta["filename"],
                    "file_size": file_meta["file_size"],
                    "mime_type": file_meta["mime_type"],
                    "checksum": file_meta["checksum"],
                    "description": description,
                    "is_public": 1 if is_public else 0,
                    "file_data_b64": base64.b64encode(
                        open(file_meta["encrypted_path"], "rb").read()
                    ).decode(),
                },
                "timestamp": file_meta["timestamp"],
                "ttl": 604800,
                "hop_count": 0,
            }
            storage.save_relay_message(relay_msg)

            flash(f"File '{uploaded.filename}' shared!", "success")
        except ValueError as e:
            flash(str(e), "error")

        return redirect(url_for("files_page"))

    @app.route("/files/download/<file_id>")
    def files_download(file_id):
        fm = app.config.get("_file_mgr")
        if not fm:
            return redirect(url_for("files_page"))

        result = fm.get_file_data(file_id)
        if not result:
            flash("File not found or cannot be decrypted.", "error")
            return redirect(url_for("files_page"))

        filename, mime_type, data = result
        return send_file(
            BytesIO(data), mimetype=mime_type,
            as_attachment=True, download_name=filename,
        )

    @app.route("/files/delete/<file_id>", methods=["POST"])
    def files_delete(file_id):
        fm = app.config.get("_file_mgr")
        if fm:
            fm.delete_file(file_id)
        return redirect(url_for("files_page"))

    # === Routes: Map ===

    @app.route("/map")
    def map_page():
        p = profile_mgr.get_local_profile()
        locations = storage.get_latest_locations()
        my_locations = storage.get_my_locations(p["fingerprint"]) if p else []
        for loc in locations:
            loc["time_ago"] = _time_ago(loc["timestamp"])
        return render_template(
            "map.html", title="Map", active="map",
            locations=locations, my_locations=my_locations,
        )

    @app.route("/map/share", methods=["POST"])
    def map_share_location():
        p = profile_mgr.get_local_profile()
        if not p:
            return jsonify({"error": "No profile"}), 400

        data = request.get_json() or request.form
        lat = data.get("latitude")
        lng = data.get("longitude")
        label = data.get("label", "").strip()

        if lat is None or lng is None:
            if request.is_json:
                return jsonify({"error": "Missing coordinates"}), 400
            flash("Missing coordinates.", "error")
            return redirect(url_for("map_page"))

        try:
            lat = float(lat)
            lng = float(lng)
        except (ValueError, TypeError):
            if request.is_json:
                return jsonify({"error": "Invalid coordinates"}), 400
            flash("Invalid coordinates.", "error")
            return redirect(url_for("map_page"))

        storage.save_location({
            "fingerprint": p["fingerprint"],
            "latitude": lat, "longitude": lng,
            "label": label, "shared": 1,
        })

        if request.is_json:
            return jsonify({"success": True})
        flash("Location shared!", "success")
        return redirect(url_for("map_page"))

    # === Routes: SOS ===

    @app.route("/sos")
    def sos_page():
        active_alerts = storage.get_active_sos()
        all_alerts = storage.get_all_sos()
        for alert in active_alerts + all_alerts:
            alert["time_ago"] = _time_ago(alert["timestamp"])
        return render_template(
            "sos.html", title="SOS", active="sos",
            active_alerts=active_alerts, all_alerts=all_alerts,
        )

    @app.route("/sos/send", methods=["POST"])
    def sos_send():
        p = profile_mgr.get_local_profile()
        if not p:
            return redirect(url_for("sos_page"))

        message = request.form.get("message", "").strip()
        severity = request.form.get("severity", "high")
        lat = request.form.get("latitude", "")
        lng = request.form.get("longitude", "")

        if not message:
            flash("SOS message required.", "error")
            return redirect(url_for("sos_page"))

        alert = {
            "alert_id": str(uuid.uuid4()),
            "sender_fingerprint": p["fingerprint"],
            "message": message, "severity": severity,
            "timestamp": int(time.time()), "ttl": 86400,
        }

        try:
            if lat and lng:
                alert["latitude"] = float(lat)
                alert["longitude"] = float(lng)
        except (ValueError, TypeError):
            pass

        storage.save_sos_alert(alert)
        relay_msg = {
            "message_id": alert["alert_id"],
            "sender_fingerprint": p["fingerprint"],
            "recipient_fingerprint": "__SOS_BROADCAST__",
            "encrypted_payload": {"type": "sos", "alert": alert},
            "timestamp": alert["timestamp"],
            "ttl": 86400, "hop_count": 0,
        }
        storage.save_relay_message(relay_msg)
        flash("SOS alert broadcast!", "success")
        return redirect(url_for("sos_page"))

    @app.route("/sos/deactivate/<alert_id>", methods=["POST"])
    def sos_deactivate(alert_id):
        storage.deactivate_sos(alert_id)
        flash("SOS alert deactivated.", "success")
        return redirect(url_for("sos_page"))

    # === Routes: Channels ===

    @app.route("/channels")
    def channels_page():
        channels = storage.get_channels()
        for ch in channels:
            ch["time_ago"] = _time_ago(ch["created_at"])
        return render_template("channels.html", title="Channels", active="channels", channels=channels)

    @app.route("/channels/create", methods=["POST"])
    def channels_create():
        p = profile_mgr.get_local_profile()
        if not p:
            return redirect(url_for("channels_page"))

        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()

        if not name or len(name) < 2 or len(name) > 50:
            flash("Invalid channel name (2-50 chars).", "error")
            return redirect(url_for("channels_page"))

        channel = {
            "channel_id": str(uuid.uuid4()),
            "name": name, "description": description,
            "creator_fingerprint": p["fingerprint"], "is_public": 1,
        }
        storage.create_channel(channel)

        relay_msg = {
            "message_id": f"ch-{channel['channel_id']}",
            "sender_fingerprint": p["fingerprint"],
            "recipient_fingerprint": "__CHANNEL_BROADCAST__",
            "encrypted_payload": {
                "type": "channel_create",
                "channel_id": channel["channel_id"],
                "name": name,
                "description": description,
                "creator_fingerprint": p["fingerprint"],
                "is_public": 1,
            },
            "timestamp": int(time.time()),
            "ttl": 604800,
            "hop_count": 0,
        }
        storage.save_relay_message(relay_msg)

        flash(f"Channel '{name}' created!", "success")
        return redirect(url_for("channel_view", channel_id=channel["channel_id"]))

    @app.route("/channels/<channel_id>")
    def channel_view(channel_id):
        channel = storage.get_channel(channel_id)
        if not channel:
            return redirect(url_for("channels_page"))
        messages = storage.get_channel_messages(channel_id)
        for msg in messages:
            msg["time_ago"] = _time_ago(msg["timestamp"])
        return render_template(
            "channel_view.html", title=f"# {channel['name']}",
            active="channels", channel=channel, messages=messages,
        )

    @app.route("/channels/<channel_id>/post", methods=["POST"])
    def channel_post(channel_id):
        p = profile_mgr.get_local_profile()
        if not p:
            return redirect(url_for("channels_page"))
        content = request.form.get("content", "").strip()
        if not content:
            return redirect(url_for("channel_view", channel_id=channel_id))

        msg_id = str(uuid.uuid4())
        storage.post_channel_message({
            "message_id": msg_id,
            "channel_id": channel_id,
            "sender_fingerprint": p["fingerprint"],
            "content": content,
        })

        relay_msg = {
            "message_id": msg_id,
            "sender_fingerprint": p["fingerprint"],
            "recipient_fingerprint": "__CHANNEL_BROADCAST__",
            "encrypted_payload": {
                "type": "channel",
                "message_id": msg_id,
                "channel_id": channel_id,
                "sender_fingerprint": p["fingerprint"],
                "content": content,
            },
            "timestamp": int(time.time()),
            "ttl": 604800,
            "hop_count": 0,
        }
        storage.save_relay_message(relay_msg)

        return redirect(url_for("channel_view", channel_id=channel_id))

    @app.route("/channels/<channel_id>/delete", methods=["POST"])
    def channel_delete(channel_id):
        storage.delete_channel(channel_id)
        flash("Channel deleted.", "success")
        return redirect(url_for("channels_page"))

    # === Routes: QR ===

    @app.route("/qr")
    def qr_page():
        p = profile_mgr.get_local_profile()
        if not p:
            return redirect(url_for("profile_page"))
        public_data = profile_mgr.export_profile_for_sharing()
        public_json = json.dumps(public_data)
        return render_template("qr.html", title="QR Code", active="qr", public_json=public_json)

    @app.route("/qr/generate")
    def qr_generate():
        p = profile_mgr.get_local_profile()
        if not p:
            return jsonify({"error": "no profile"}), 404

        try:
            import qrcode
            public_data = profile_mgr.export_profile_for_sharing()
            qr_data = json.dumps(public_data)
            qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=8, border=2)
            qr.add_data(qr_data)
            qr.make(fit=True)
            img = qr.make_image(fill_color="#00ff88", back_color="#0a0e17")
            buffer = BytesIO()
            img.save(buffer, format="PNG")
            buffer.seek(0)
            return send_file(buffer, mimetype="image/png", download_name="meshbox-qr.png")
        except ImportError:
            return jsonify({"error": "qrcode module not installed"}), 500

    # === API JSON ===

    @app.route("/api/status")
    def api_status():
        return jsonify(storage.get_stats())

    @app.route("/api/profile")
    def api_profile():
        p = profile_mgr.get_local_profile()
        if p:
            return jsonify(p)
        return jsonify({"error": "no profile"}), 404

    @app.route("/api/contacts")
    def api_contacts():
        return jsonify(profile_mgr.get_all_contacts())

    @app.route("/api/inbox")
    def api_inbox():
        p = profile_mgr.get_local_profile()
        if not p:
            return jsonify([])
        messages = storage.get_inbox(p["fingerprint"])
        for msg in messages:
            sender = storage.get_profile(msg["sender_fingerprint"])
            msg["sender_name"] = sender["name"] if sender else msg["sender_fingerprint"][:12]
            msg["time_ago"] = _time_ago(msg["timestamp"])
        return jsonify(messages)

    @app.route("/api/peers")
    def api_peers():
        peers = storage.get_recent_peers(20)
        for peer in peers:
            peer["time_ago"] = _time_ago(peer["seen_at"])
        return jsonify(peers)

    @app.route("/api/sos")
    def api_sos():
        return jsonify(storage.get_active_sos())

    @app.route("/api/locations")
    def api_locations():
        return jsonify(storage.get_latest_locations())

    @app.route("/api/channels")
    def api_channels():
        return jsonify(storage.get_channels())

    @app.route("/api/files")
    def api_files():
        p = profile_mgr.get_local_profile()
        if not p:
            return jsonify([])
        return jsonify(storage.get_public_files())

    return app


def main():
    app = create_app()
    app.run(host="127.0.0.1", port=8080, debug=False)
