#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/usr/lib/vpn-tray"
APP_PATH="${APP_DIR}/vpn-tray.py"
HELPER_PATH="${APP_DIR}/vpn-tray-helper.sh"
LAUNCHER_PATH="/usr/bin/vpn-tray"
SUDOERS_TARGET="/etc/sudoers.d/vpn-tray"
UNIT_NAME="vpn-tray.service"

INSTALL_USER="${SUDO_USER:-${USER}}"

usage() {
    cat <<'EOF'
Usage: ./uninstall.sh [--user <name>]
EOF
}

fail() {
    echo "[uninstall] $*" >&2
    exit 1
}

run_as_user() {
    if [ "$(id -un)" = "$INSTALL_USER" ]; then
        "$@"
    else
        sudo -u "$INSTALL_USER" "$@"
    fi
}

while [ $# -gt 0 ]; do
    case "$1" in
        --user)
            INSTALL_USER="$2"
            shift 2
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

id "$INSTALL_USER" >/dev/null 2>&1 || fail "User does not exist: $INSTALL_USER"
INSTALL_UID="$(id -u "$INSTALL_USER")"
SYSTEMD_USER_RUNTIME="/run/user/${INSTALL_UID}"
SYSTEMD_USER_BUS="${SYSTEMD_USER_RUNTIME}/bus"

sudo -v

if [ -S "$SYSTEMD_USER_BUS" ]; then
    run_as_user env XDG_RUNTIME_DIR="$SYSTEMD_USER_RUNTIME" DBUS_SESSION_BUS_ADDRESS="unix:path=${SYSTEMD_USER_BUS}" systemctl --user disable --now "$UNIT_NAME" || true
    run_as_user rm -f "$(getent passwd "$INSTALL_USER" | cut -d: -f6)/.config/systemd/user/${UNIT_NAME}" || true
    run_as_user env XDG_RUNTIME_DIR="$SYSTEMD_USER_RUNTIME" DBUS_SESSION_BUS_ADDRESS="unix:path=${SYSTEMD_USER_BUS}" systemctl --user daemon-reload || true
fi

sudo rm -f "$SUDOERS_TARGET"
sudo rm -f "$LAUNCHER_PATH"
sudo rm -f "$APP_PATH" "$HELPER_PATH"
sudo rmdir "$APP_DIR" 2>/dev/null || true

echo "[uninstall] Done"
