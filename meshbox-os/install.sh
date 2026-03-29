#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# MeshBox OS — Installation & Service Setup
# Installs dependencies, the meshbox package, and configures
# background services (daemon + web UI).
# Supports: macOS (launchd) and Linux (systemd).
# ═══════════════════════════════════════════════════════════════
set -euo pipefail

# ── Colours ───────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; NC='\033[0m'

info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail()  { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ── Detect OS ─────────────────────────────────────────────────
OS="$(uname -s)"
case "$OS" in
    Linux*)  PLATFORM="linux";;
    Darwin*) PLATFORM="macos";;
    *)       fail "Unsupported OS: $OS";;
esac
info "Detected platform: $PLATFORM"

# ── Resolve real user when running under sudo ─────────────────
if [[ -n "${SUDO_UID:-}" ]]; then
    REAL_UID="$SUDO_UID"
    REAL_USER="${SUDO_USER:-$(id -un "$SUDO_UID")}"
    REAL_HOME=$(eval echo "~$REAL_USER")
else
    REAL_UID="$(id -u)"
    REAL_USER="$(id -un)"
    REAL_HOME="$HOME"
fi

# ── Locate project root (same dir as this script) ────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
info "Project directory: $SCRIPT_DIR"

# ── Check Python >=3.9 ───────────────────────────────────────
PYTHON=""
for candidate in python3 python; do
    if command -v "$candidate" &>/dev/null; then
        ver="$("$candidate" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
        major="${ver%%.*}"
        minor="${ver##*.}"
        if (( major >= 3 && minor >= 9 )); then
            PYTHON="$candidate"
            break
        fi
    fi
done

if [[ -z "$PYTHON" ]]; then
    warn "Python >=3.9 not found. Attempting to install..."
    if [[ "$PLATFORM" == "macos" ]]; then
        if command -v brew &>/dev/null; then
            brew install python@3.12
            PYTHON="python3"
        else
            fail "Homebrew not found. Install Python 3.9+ manually: https://www.python.org/downloads/"
        fi
    else
        if command -v apt-get &>/dev/null; then
            sudo apt-get update && sudo apt-get install -y python3 python3-pip python3-venv
            PYTHON="python3"
        elif command -v dnf &>/dev/null; then
            sudo dnf install -y python3 python3-pip
            PYTHON="python3"
        elif command -v pacman &>/dev/null; then
            sudo pacman -S --noconfirm python python-pip
            PYTHON="python3"
        else
            fail "Could not install Python. Install Python 3.9+ manually."
        fi
    fi
fi

PYTHON_PATH="$(command -v "$PYTHON")"
PYTHON_VER="$("$PYTHON" --version 2>&1)"
ok "Using $PYTHON_VER ($PYTHON_PATH)"

# ── Ensure pip is available ───────────────────────────────────
if ! "$PYTHON" -m pip --version &>/dev/null; then
    warn "pip not found, installing..."
    "$PYTHON" -m ensurepip --upgrade 2>/dev/null || true
    "$PYTHON" -m pip --version &>/dev/null || fail "Cannot install pip. Please install it manually."
fi
ok "pip available"

# ── Create / reuse a virtual environment ──────────────────────
# Use ~/.meshbox/venv so launchd can access it (macOS blocks ~/Documents)
VENV_DIR="${MESHBOX_DATA_DIR:-$REAL_HOME/.meshbox}/venv"
mkdir -p "$(dirname "$VENV_DIR")"
if [[ ! -d "$VENV_DIR" ]]; then
    info "Creating virtual environment in $VENV_DIR ..."
    "$PYTHON" -m venv "$VENV_DIR"
fi
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
ok "Virtual environment activated ($VENV_DIR)"

# ── Upgrade pip inside the venv ───────────────────────────────
pip install --upgrade pip setuptools wheel -q
ok "pip / setuptools / wheel up to date"

# ── Install MeshBox with all extras ──────────────────────────
# Use non-editable install so all code lives inside the venv
# (editable mode symlinks to Documents/ which launchd can't read on macOS)
info "Installing meshbox with all optional dependencies..."
pip install "$SCRIPT_DIR[all]" -q
ok "meshbox installed ($(meshbox --version 2>&1 || echo 'v?'))"

# ── Determine paths for services ──────────────────────────────
MESHBOX_BIN="$(command -v meshbox)"
MESHBOX_DATA_DIR="${MESHBOX_DATA_DIR:-$REAL_HOME/.meshbox}"
export MESHBOX_DATA_DIR
mkdir -p "$MESHBOX_DATA_DIR"

# ── Fix ownership if running under sudo ───────────────────────
if [[ -n "${SUDO_UID:-}" ]]; then
    chown -R "$REAL_USER" "$MESHBOX_DATA_DIR"
    chown -R "$REAL_USER" "$VENV_DIR"
fi

info "meshbox binary : $MESHBOX_BIN"
info "Data directory : $MESHBOX_DATA_DIR"

# ══════════════════════════════════════════════════════════════
#  SERVICE INSTALLATION
# ══════════════════════════════════════════════════════════════

install_systemd_services() {
    info "Setting up systemd user services..."

    local unit_dir="$REAL_HOME/.config/systemd/user"
    mkdir -p "$unit_dir"

    # ── meshbox-daemon.service ────────────────────────────────
    cat > "$unit_dir/meshbox-daemon.service" <<EOF
[Unit]
Description=MeshBox Mesh Network Daemon
After=network.target

[Service]
Type=simple
ExecStart=$VENV_DIR/bin/meshbox daemon --log-level INFO
Environment=MESHBOX_DATA_DIR=$MESHBOX_DATA_DIR
Environment=PATH=$VENV_DIR/bin:/usr/local/bin:/usr/bin:/bin
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
EOF
    ok "Created meshbox-daemon.service"

    # ── meshbox-web.service ───────────────────────────────────
    cat > "$unit_dir/meshbox-web.service" <<EOF
[Unit]
Description=MeshBox Web UI
After=network.target meshbox-daemon.service

[Service]
Type=simple
ExecStart=$VENV_DIR/bin/meshbox web --host 0.0.0.0 --port 8080
Environment=MESHBOX_DATA_DIR=$MESHBOX_DATA_DIR
Environment=PATH=$VENV_DIR/bin:/usr/local/bin:/usr/bin:/bin
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
EOF
    ok "Created meshbox-web.service"

    # ── Fix ownership if running under sudo ───────────────────
    if [[ -n "${SUDO_UID:-}" ]]; then
        chown -R "$REAL_USER" "$REAL_HOME/.config/systemd"
    fi

    # ── Enable & start ────────────────────────────────────────
    # When running under sudo, systemctl --user needs the real user's
    # D-Bus session bus. We use machinectl or fall back to sudo -u
    # with XDG_RUNTIME_DIR set.
    local run_as_user=""
    if [[ -n "${SUDO_UID:-}" ]]; then
        local xdg_runtime="/run/user/$REAL_UID"
        if [[ -d "$xdg_runtime" ]]; then
            run_as_user="sudo -u $REAL_USER XDG_RUNTIME_DIR=$xdg_runtime DBUS_SESSION_BUS_ADDRESS=unix:path=$xdg_runtime/bus"
        elif command -v machinectl &>/dev/null; then
            # machinectl approach — works even without XDG_RUNTIME_DIR
            run_as_user="machinectl shell --uid=$REAL_USER .host /bin/bash -c"
        fi
    fi

    if [[ -n "$run_as_user" ]] && [[ "$run_as_user" == machinectl* ]]; then
        $run_as_user "systemctl --user daemon-reload && systemctl --user enable meshbox-daemon.service meshbox-web.service && systemctl --user start meshbox-daemon.service meshbox-web.service"
    elif [[ -n "$run_as_user" ]]; then
        $run_as_user systemctl --user daemon-reload
        $run_as_user systemctl --user enable meshbox-daemon.service meshbox-web.service
        $run_as_user systemctl --user start  meshbox-daemon.service meshbox-web.service
    else
        systemctl --user daemon-reload
        systemctl --user enable meshbox-daemon.service meshbox-web.service
        systemctl --user start  meshbox-daemon.service meshbox-web.service
    fi
    ok "systemd services enabled and started"

    # ── Enable lingering so user services start at boot ───────
    loginctl enable-linger "$REAL_USER" 2>/dev/null || true

    echo ""
    info "Useful commands:"
    echo "  systemctl --user status  meshbox-daemon"
    echo "  systemctl --user status  meshbox-web"
    echo "  systemctl --user restart meshbox-daemon"
    echo "  systemctl --user restart meshbox-web"
    echo "  journalctl --user -u meshbox-daemon -f"
    echo "  journalctl --user -u meshbox-web -f"
    echo "  systemctl --user stop meshbox-daemon meshbox-web"
    echo "  systemctl --user disable meshbox-daemon meshbox-web"
}

install_launchd_services() {
    info "Setting up macOS launchd services..."

    local plist_dir="$REAL_HOME/Library/LaunchAgents"
    mkdir -p "$plist_dir"

    # ── com.meshbox.daemon.plist ──────────────────────────────
    cat > "$plist_dir/com.meshbox.daemon.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.meshbox.daemon</string>
    <key>ProgramArguments</key>
    <array>
        <string>$VENV_DIR/bin/meshbox</string>
        <string>daemon</string>
        <string>--log-level</string>
        <string>INFO</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>MESHBOX_DATA_DIR</key>
        <string>$MESHBOX_DATA_DIR</string>
        <key>PATH</key>
        <string>$VENV_DIR/bin:/usr/local/bin:/usr/bin:/bin</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$MESHBOX_DATA_DIR/logs/daemon.log</string>
    <key>StandardErrorPath</key>
    <string>$MESHBOX_DATA_DIR/logs/daemon.err</string>
</dict>
</plist>
EOF
    ok "Created com.meshbox.daemon.plist"

    # ── com.meshbox.web.plist ─────────────────────────────────
    cat > "$plist_dir/com.meshbox.web.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.meshbox.web</string>
    <key>ProgramArguments</key>
    <array>
        <string>$VENV_DIR/bin/meshbox</string>
        <string>web</string>
        <string>--host</string>
        <string>0.0.0.0</string>
        <string>--port</string>
        <string>8080</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>MESHBOX_DATA_DIR</key>
        <string>$MESHBOX_DATA_DIR</string>
        <key>PATH</key>
        <string>$VENV_DIR/bin:/usr/local/bin:/usr/bin:/bin</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$MESHBOX_DATA_DIR/logs/web.log</string>
    <key>StandardErrorPath</key>
    <string>$MESHBOX_DATA_DIR/logs/web.err</string>
</dict>
</plist>
EOF
    ok "Created com.meshbox.web.plist"

    # ── Create log directory ──────────────────────────────────
    mkdir -p "$MESHBOX_DATA_DIR/logs"

    # ── Fix ownership if running under sudo ───────────────────
    if [[ -n "${SUDO_UID:-}" ]]; then
        chown "$REAL_USER" "$plist_dir/com.meshbox.daemon.plist" "$plist_dir/com.meshbox.web.plist"
        chown -R "$REAL_USER" "$MESHBOX_DATA_DIR"
    fi

    # ── Unload existing (ignore errors) then load ─────────────
    launchctl bootout "gui/$REAL_UID/com.meshbox.daemon" 2>/dev/null || true
    launchctl bootout "gui/$REAL_UID/com.meshbox.web"    2>/dev/null || true
    launchctl bootstrap "gui/$REAL_UID" "$plist_dir/com.meshbox.daemon.plist"
    launchctl bootstrap "gui/$REAL_UID" "$plist_dir/com.meshbox.web.plist"
    ok "launchd services loaded and running"

    echo ""
    info "Useful commands:"
    echo "  launchctl list | grep meshbox"
    echo "  launchctl kickstart -k gui/$REAL_UID/com.meshbox.daemon   # restart daemon"
    echo "  launchctl kickstart -k gui/$REAL_UID/com.meshbox.web      # restart web"
    echo "  tail -f $MESHBOX_DATA_DIR/logs/daemon.log"
    echo "  tail -f $MESHBOX_DATA_DIR/logs/web.log"
    echo ""
    echo "  # To stop services:"
    echo "  launchctl bootout gui/$REAL_UID/com.meshbox.daemon"
    echo "  launchctl bootout gui/$REAL_UID/com.meshbox.web"
}

# ══════════════════════════════════════════════════════════════
#  CHECK IF PROFILE EXISTS — remind user to create one
# ══════════════════════════════════════════════════════════════

if [[ ! -d "$MESHBOX_DATA_DIR/keys" ]] || [[ -z "$(ls -A "$MESHBOX_DATA_DIR/keys" 2>/dev/null)" ]]; then
    warn "No MeshBox profile found."
    echo ""
    read -rp "Enter your name/alias to create a profile now: " MB_NAME
    if [[ -n "$MB_NAME" ]]; then
        meshbox profile create --name "$MB_NAME"
        ok "Profile created for '$MB_NAME'"
    else
        warn "Skipped. Create a profile later with: meshbox profile create --name 'YourName'"
        warn "The daemon will NOT start until a profile exists."
    fi
fi

# ══════════════════════════════════════════════════════════════
#  TOR INSTALLATION & CONFIGURATION
# ══════════════════════════════════════════════════════════════

install_tor() {
    info "Setting up Tor for .onion hidden service..."

    # ── Install Tor if not present ────────────────────────────
    if ! command -v tor &>/dev/null; then
        info "Installing Tor..."
        if [[ "$PLATFORM" == "macos" ]]; then
            if command -v brew &>/dev/null; then
                brew install tor
            else
                fail "Homebrew not found. Install Tor manually: brew install tor"
            fi
        else
            if command -v apt-get &>/dev/null; then
                sudo apt-get update && sudo apt-get install -y tor
            elif command -v dnf &>/dev/null; then
                sudo dnf install -y tor
            elif command -v pacman &>/dev/null; then
                sudo pacman -S --noconfirm tor
            else
                warn "Could not install Tor automatically. Install it manually."
                return 1
            fi
        fi
        ok "Tor installed ($(tor --version | head -1))"
    else
        ok "Tor already installed ($(tor --version | head -1))"
    fi

    # ── Helper: check if a port is open ───────────────────────
    # nc may not be installed on minimal Raspberry Pi OS images
    check_port() {
        local host="$1" port="$2"
        if command -v nc &>/dev/null; then
            nc -z "$host" "$port" 2>/dev/null
        elif command -v ss &>/dev/null; then
            ss -tlnH "sport = :$port" 2>/dev/null | grep -q LISTEN
        elif [[ -e /dev/tcp/$host/$port ]]; then
            (echo >/dev/tcp/"$host"/"$port") 2>/dev/null
        else
            # last resort: try bash built-in /dev/tcp
            bash -c "(echo >/dev/tcp/$host/$port) 2>/dev/null"
        fi
    }

    # ── Configure Tor with ControlPort ────────────────────────
    if [[ "$PLATFORM" == "macos" ]]; then
        TORRC="/opt/homebrew/etc/tor/torrc"
        # Fallback for Intel Macs
        [[ ! -d "/opt/homebrew/etc/tor" ]] && TORRC="/usr/local/etc/tor/torrc"
    else
        TORRC="/etc/tor/torrc"
    fi

    local torrc_dir
    torrc_dir="$(dirname "$TORRC")"
    mkdir -p "$torrc_dir"

    # Create torrc if it doesn't exist (shouldn't happen, but be safe)
    [[ -f "$TORRC" ]] || touch "$TORRC"

    # Append needed directives without overwriting existing config
    local tor_changed=false
    if ! grep -q "^SocksPort 9050" "$TORRC" 2>/dev/null; then
        echo "SocksPort 9050" >> "$TORRC"
        tor_changed=true
    fi
    if ! grep -q "^ControlPort 9051" "$TORRC" 2>/dev/null; then
        echo "ControlPort 9051" >> "$TORRC"
        tor_changed=true
    fi
    if ! grep -q "^CookieAuthentication 1" "$TORRC" 2>/dev/null; then
        echo "CookieAuthentication 1" >> "$TORRC"
        tor_changed=true
    fi
    # Allow group members (debian-tor) to read the cookie file
    if ! grep -q "^CookieAuthFileGroupReadable 1" "$TORRC" 2>/dev/null; then
        echo "CookieAuthFileGroupReadable 1" >> "$TORRC"
        tor_changed=true
    fi
    if [[ "$tor_changed" == true ]]; then
        ok "Tor configured ($TORRC)"
    else
        ok "Tor already configured with ControlPort"
    fi

    # ── On Linux, add user to debian-tor group for cookie auth ─
    if [[ "$PLATFORM" == "linux" ]] && getent group debian-tor &>/dev/null; then
        if ! id -nG "$REAL_USER" | grep -qw debian-tor; then
            info "Adding $REAL_USER to debian-tor group (cookie auth)..."
            sudo usermod -aG debian-tor "$REAL_USER"
            ok "$REAL_USER added to debian-tor group"
        fi
        # Ensure the cookie file is group-readable
        local cookie="/run/tor/control.authcookie"
        [[ -f "$cookie" ]] && sudo chmod g+r "$cookie" 2>/dev/null || true
    fi

    # ── Verify config is valid before restarting ──────────────
    info "Verifying Tor configuration..."
    if ! sudo -u debian-tor tor --verify-config -f "$TORRC" 2>/dev/null \
       && ! tor --verify-config -f "$TORRC" 2>/dev/null; then
        warn "Tor config verification failed. Dumping torrc:"
        cat "$TORRC"
        warn "Fix the errors above and re-run install.sh"
        return 1
    fi
    ok "Tor configuration valid"

    # ── Start / restart Tor service ───────────────────────────
    if [[ "$PLATFORM" == "macos" ]]; then
        if ! brew services list | grep -q "tor.*started"; then
            info "Starting Tor service..."
            brew services start tor
            ok "Tor service started"
        elif [[ "$tor_changed" == true ]]; then
            info "Restarting Tor service (config changed)..."
            brew services restart tor
            ok "Tor service restarted"
        else
            ok "Tor service already running"
        fi
    else
        sudo systemctl enable tor
        info "Restarting Tor service..."
        sudo systemctl restart tor
        sleep 2

        # ── Check if Tor actually started ─────────────────────
        if ! systemctl is-active --quiet tor 2>/dev/null; then
            warn "Tor failed to start. Service status:"
            sudo systemctl status tor --no-pager -l 2>&1 | tail -20
            echo ""
            warn "Last Tor log entries:"
            sudo journalctl -u tor --no-pager -n 15 2>&1 || true
            return 1
        fi
        ok "Tor service running"
    fi

    # ── Wait for Tor ControlPort to be ready ──────────────────
    local max_wait=60
    info "Waiting for Tor ControlPort (up to ${max_wait}s)..."
    local retries=0
    while ! check_port 127.0.0.1 9051; do
        retries=$((retries + 1))
        if (( retries > max_wait )); then
            warn "Tor ControlPort not reachable after ${max_wait}s."
            if [[ "$PLATFORM" == "linux" ]]; then
                warn "Tor service status:"
                sudo systemctl status tor --no-pager -l 2>&1 | tail -10
                echo ""
                warn "Recent Tor logs:"
                sudo journalctl -u tor --no-pager -n 20 2>&1 || true
            fi
            warn "MeshBox daemon will retry Tor connection on start."
            return 0
        fi
        sleep 1
    done
    ok "Tor ControlPort ready"
}

install_tor

# ── Install services ──────────────────────────────────────────
if [[ "$PLATFORM" == "linux" ]]; then
    install_systemd_services
elif [[ "$PLATFORM" == "macos" ]]; then
    install_launchd_services
fi

# ══════════════════════════════════════════════════════════════
#  DONE
# ══════════════════════════════════════════════════════════════
echo ""
echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  MeshBox installation complete!${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
echo ""
echo "  Daemon ➜  running in background (mesh networking)"
echo "  Web UI ➜  http://0.0.0.0:8080  (accessible on local network)"
echo "  Data   ➜  $MESHBOX_DATA_DIR"
echo "  Venv   ➜  $VENV_DIR"
echo ""
echo "  CLI examples:"
echo "    meshbox inbox"
echo "    meshbox send --to <fingerprint> --message 'Hello!'"
echo "    meshbox contacts list"
echo ""
