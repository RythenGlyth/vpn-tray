#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

APP_DIR="/usr/lib/vpn-tray"
APP_PATH="${APP_DIR}/vpn-tray.py"
HELPER_PATH="${APP_DIR}/vpn-tray-helper.sh"
LAUNCHER_PATH="/usr/bin/vpn-tray"
SUDOERS_TARGET="/etc/sudoers.d/vpn-tray"
UNIT_NAME="vpn-tray.service"

INSTALL_USER="${SUDO_USER:-${USER}}"
VPN_TRAY_RUNTIME_DIR="%t/vpn-tray"
VPN_TRAY_PID_FILENAME="vpn_tray.pid"
VPN_TRAY_LOCK_FILE="%t/vpn-tray.lock"
UPDATE_MODE="0"

usage() {
    cat <<'EOF'
Usage: ./install.sh [options]

Options:
  --user <name>                  Install/enable user service for this user (default: current user)
    --runtime-dir <path>           VPN_TRAY_RUNTIME_DIR (default: %t/vpn-tray)
    --pid-filename <name>          VPN_TRAY_PID_FILENAME (default: vpn_tray.pid)
    --lock-file <path>             VPN_TRAY_LOCK_FILE (default: %t/vpn-tray.lock)
    --update                       Update mode: force restart vpn-tray.service after install
  -h, --help                     Show this help
EOF
}

fail() {
    echo "[install] $*" >&2
    exit 1
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || fail "Missing required command: $1"
}

run_as_user() {
    if [ "$(id -un)" = "$INSTALL_USER" ]; then
        "$@"
    else
        sudo -u "$INSTALL_USER" "$@"
    fi
}

render_template() {
    local template_file="$1"
    local output_file="$2"

    python3 - "$template_file" "$output_file" <<'PY'
import os
import sys

src, dst = sys.argv[1], sys.argv[2]
text = open(src, 'r', encoding='utf-8').read()
for key, value in {
    'INSTALL_USER': os.environ['INSTALL_USER'],
    'HELPER_PATH': os.environ['HELPER_PATH'],
    'VPN_TRAY_HELPER': os.environ['HELPER_PATH'],
    'VPN_TRAY_RUNTIME_DIR': os.environ['VPN_TRAY_RUNTIME_DIR'],
    'VPN_TRAY_PID_FILENAME': os.environ['VPN_TRAY_PID_FILENAME'],
    'VPN_TRAY_LOCK_FILE': os.environ['VPN_TRAY_LOCK_FILE'],
}.items():
    text = text.replace(f'@{key}@', value)
open(dst, 'w', encoding='utf-8').write(text)
PY
}

while [ $# -gt 0 ]; do
    case "$1" in
        --user)
            INSTALL_USER="$2"
            shift 2
            ;;
        --runtime-dir)
            VPN_TRAY_RUNTIME_DIR="$2"
            shift 2
            ;;
        --pid-filename)
            VPN_TRAY_PID_FILENAME="$2"
            shift 2
            ;;
        --lock-file)
            VPN_TRAY_LOCK_FILE="$2"
            shift 2
            ;;
        --update)
            UPDATE_MODE="1"
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            fail "Unknown argument: $1"
            ;;
    esac
done

require_cmd sudo
require_cmd systemctl
require_cmd visudo
require_cmd install
require_cmd python3
require_cmd openconnect
require_cmd oathtool

python3 - <<'PY' >/dev/null 2>&1 || fail "PyQt6/keyring is not importable for python3"
import PyQt6  # noqa: F401
import keyring  # noqa: F401
PY

[ -f "${SCRIPT_DIR}/vpn-tray.py" ] || fail "Missing source file: vpn-tray.py"
[ -f "${SCRIPT_DIR}/vpn-tray-helper.sh" ] || fail "Missing source file: vpn-tray-helper.sh"
[ -f "${SCRIPT_DIR}/packaging/systemd/vpn-tray.service" ] || fail "Missing unit template: packaging/systemd/vpn-tray.service"
[ -f "${SCRIPT_DIR}/packaging/sudoers/vpn-tray" ] || fail "Missing sudoers template: packaging/sudoers/vpn-tray"

id "$INSTALL_USER" >/dev/null 2>&1 || fail "User does not exist: $INSTALL_USER"
INSTALL_UID="$(id -u "$INSTALL_USER")"
USER_HOME="$(getent passwd "$INSTALL_USER" | cut -d: -f6)"
[ -n "$USER_HOME" ] || fail "Could not determine home for user: $INSTALL_USER"

SYSTEMD_USER_RUNTIME="/run/user/${INSTALL_UID}"
SYSTEMD_USER_BUS="${SYSTEMD_USER_RUNTIME}/bus"
[ -d "$SYSTEMD_USER_RUNTIME" ] || fail "No runtime dir for user $INSTALL_USER at ${SYSTEMD_USER_RUNTIME}. Log in graphically first."
[ -S "$SYSTEMD_USER_BUS" ] || fail "No user DBus socket at ${SYSTEMD_USER_BUS}. Ensure the user systemd session is running."

echo "[install] Requesting sudo credentials..."
sudo -v

echo "[install] Installing app files to ${APP_DIR}"
sudo install -d -m 0755 "$APP_DIR"
sudo install -m 0755 "${SCRIPT_DIR}/vpn-tray.py" "$APP_PATH"
sudo install -m 0755 "${SCRIPT_DIR}/vpn-tray-helper.sh" "$HELPER_PATH"

launcher_tmp="$(mktemp)"
cat > "$launcher_tmp" <<EOF
#!/usr/bin/env bash
exec /usr/bin/python3 ${APP_PATH} "\$@"
EOF
sudo install -m 0755 "$launcher_tmp" "$LAUNCHER_PATH"
rm -f "$launcher_tmp"

echo "[install] Installing least-privilege sudoers policy"
export INSTALL_USER HELPER_PATH VPN_TRAY_RUNTIME_DIR VPN_TRAY_PID_FILENAME
export VPN_TRAY_LOCK_FILE

sudoers_tmp="$(mktemp)"
render_template "${SCRIPT_DIR}/packaging/sudoers/vpn-tray" "$sudoers_tmp"
sudo install -o root -g root -m 0440 "$sudoers_tmp" "$SUDOERS_TARGET"
rm -f "$sudoers_tmp"
sudo visudo -cf "$SUDOERS_TARGET" >/dev/null || fail "sudoers validation failed"

echo "[install] Installing user systemd unit"
unit_tmp="$(mktemp)"
render_template "${SCRIPT_DIR}/packaging/systemd/vpn-tray.service" "$unit_tmp"
chmod 0644 "$unit_tmp"
run_as_user install -d -m 0755 "${USER_HOME}/.config/systemd/user"
run_as_user install -m 0644 "$unit_tmp" "${USER_HOME}/.config/systemd/user/${UNIT_NAME}"
rm -f "$unit_tmp"

echo "[install] Reloading and enabling user service"
run_as_user env XDG_RUNTIME_DIR="$SYSTEMD_USER_RUNTIME" DBUS_SESSION_BUS_ADDRESS="unix:path=${SYSTEMD_USER_BUS}" systemctl --user daemon-reload
run_as_user env XDG_RUNTIME_DIR="$SYSTEMD_USER_RUNTIME" DBUS_SESSION_BUS_ADDRESS="unix:path=${SYSTEMD_USER_BUS}" systemctl --user enable --now "$UNIT_NAME"
if [ "$UPDATE_MODE" = "1" ]; then
    echo "[install] Update mode active: restarting user service"
    run_as_user env XDG_RUNTIME_DIR="$SYSTEMD_USER_RUNTIME" DBUS_SESSION_BUS_ADDRESS="unix:path=${SYSTEMD_USER_BUS}" systemctl --user restart "$UNIT_NAME"
fi

echo "[install] Done"
if [ "$UPDATE_MODE" = "1" ]; then
    echo "[install] Update summary: refreshed files, validated sudoers, reloaded and restarted ${UNIT_NAME}"
fi
echo
echo "Post-install checks:"
echo "  command -v vpn-tray"
echo "  ls -l ${APP_PATH} ${HELPER_PATH} ${LAUNCHER_PATH}"
echo "  sudo visudo -cf ${SUDOERS_TARGET}"
echo "  sudo cat ${SUDOERS_TARGET}"
echo "  sudo -n ${HELPER_PATH} reset ${VPN_TRAY_PID_FILENAME}"
echo "  sudo -n ${HELPER_PATH} stop ${VPN_TRAY_PID_FILENAME}"
echo "  sudo -u ${INSTALL_USER} env XDG_RUNTIME_DIR=${SYSTEMD_USER_RUNTIME} DBUS_SESSION_BUS_ADDRESS=unix:path=${SYSTEMD_USER_BUS} systemctl --user status ${UNIT_NAME}"
