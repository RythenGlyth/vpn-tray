#!/bin/bash
# Hardened privileged helper script for VPN tray
set -u

COMMAND="${1:-}"
PID_FILENAME="${2:-}"
RUNTIME_DIR="${VPN_TRAY_RUNTIME_DIR:-}"

usage() {
    echo "Usage: vpn-tray-helper.sh {start|stop|reset} <pid_filename> [server] [user]" >&2
}

fail() {
    echo "Error: $1" >&2
    exit 1
}

sanitize_pid_filename() {
    local name="$1"
    if [ -z "$name" ] || [ "$name" = "." ] || [ "$name" = ".." ]; then
        return 1
    fi
    if [[ ! "$name" =~ ^[A-Za-z0-9._-]{1,64}$ ]]; then
        return 1
    fi
    return 0
}

is_openconnect_pid() {
    local pid="$1"
    local comm

    if [ ! -r "/proc/${pid}/comm" ]; then
        return 1
    fi
    read -r comm < "/proc/${pid}/comm" || return 1
    [ "$comm" = "openconnect" ]
}

wait_for_pid_exit() {
    local pid="$1"
    local timeout_seconds="${2:-8}"
    local elapsed=0

    while is_openconnect_pid "$pid"; do
        if [ "$elapsed" -ge "$timeout_seconds" ]; then
            return 1
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    return 0
}

graceful_stop_openconnect_pid() {
    local pid="$1"

    if ! is_openconnect_pid "$pid"; then
        return 0
    fi

    # Prefer graceful termination first so vpnc-script disconnect hooks can run.
    kill -SIGTERM -- "$pid" 2>/dev/null || true
    if wait_for_pid_exit "$pid" 10; then
        return 0
    fi

    # Fallback to SIGINT, then hard-kill if still present.
    kill -SIGINT -- "$pid" 2>/dev/null || true
    if wait_for_pid_exit "$pid" 4; then
        return 0
    fi

    kill -KILL -- "$pid" 2>/dev/null || true
    return 0
}

list_all_openconnect_pids() {
    ps -eo pid=,comm= | awk '$2 == "openconnect" { print $1 }'
}

post_disconnect_dns_cleanup() {
    # Best-effort cleanup for occasional stale resolver state after tunnel teardown.
    if command -v resolvectl >/dev/null 2>&1; then
        resolvectl revert >/dev/null 2>&1 || true
        resolvectl flush-caches >/dev/null 2>&1 || true
    fi

    if command -v nmcli >/dev/null 2>&1; then
        nmcli general reload >/dev/null 2>&1 || true
    fi
}

read_pid_from_file() {
    local file="$1"
    local pid

    [ -f "$file" ] || return 1
    [ -L "$file" ] && return 1

    read -r pid < "$file" || return 1
    [[ "$pid" =~ ^[0-9]+$ ]] || return 1
    echo "$pid"
    return 0
}

resolve_runtime_dir() {
    local uid_for_runtime

    if [ -n "$RUNTIME_DIR" ]; then
        return 0
    fi

    uid_for_runtime="${SUDO_UID:-${UID}}"

    if [ -d "/run/user/${uid_for_runtime}" ]; then
        RUNTIME_DIR="/run/user/${uid_for_runtime}/vpn-tray"
        return 0
    fi

    if [ -n "${XDG_RUNTIME_DIR:-}" ] && [ -d "$XDG_RUNTIME_DIR" ]; then
        RUNTIME_DIR="${XDG_RUNTIME_DIR}/vpn-tray"
        return 0
    fi

    RUNTIME_DIR="/tmp/vpn-tray-${uid_for_runtime}"
    return 0
}

[ -n "$COMMAND" ] || { usage; exit 1; }
sanitize_pid_filename "$PID_FILENAME" || fail "Invalid PID filename."
resolve_runtime_dir

[ -L "$RUNTIME_DIR" ] && fail "Runtime directory must not be a symlink."
if [ ! -d "$RUNTIME_DIR" ]; then
    umask 077
    mkdir -p "$RUNTIME_DIR" || fail "Cannot create runtime directory: $RUNTIME_DIR"
fi
chmod 0700 "$RUNTIME_DIR" 2>/dev/null || true

PID_FILE="${RUNTIME_DIR}/${PID_FILENAME}"

[ -L "$PID_FILE" ] && fail "PID file must not be a symlink."

if [ "$COMMAND" = "start" ]; then
    SERVER="${3:-}"
    USERNAME="${4:-}"

    if [ -z "$SERVER" ] || [ -z "$USERNAME" ]; then
        fail "Missing server or username."
    fi
    if [[ "$SERVER" == -* ]] || [[ "$USERNAME" == -* ]]; then
        fail "Server and username cannot start with a hyphen."
    fi

    if [ -e "$PID_FILE" ] && [ ! -f "$PID_FILE" ]; then
        fail "PID path exists and is not a regular file."
    fi

    exec openconnect "$SERVER" -u "$USERNAME" --useragent=AnyConnect --no-external-auth --background --pid-file="$PID_FILE" -v

elif [ "$COMMAND" = "stop" ]; then
    PID="$(read_pid_from_file "$PID_FILE" 2>/dev/null || true)"

    if [ -n "$PID" ] && is_openconnect_pid "$PID"; then
        graceful_stop_openconnect_pid "$PID"
    fi

    rm -f -- "$PID_FILE"
    post_disconnect_dns_cleanup

elif [ "$COMMAND" = "reset" ]; then
    PID="$(read_pid_from_file "$PID_FILE" 2>/dev/null || true)"

    if [ -n "$PID" ] && is_openconnect_pid "$PID"; then
        graceful_stop_openconnect_pid "$PID"
    fi

    # Emergency reset: terminate any remaining openconnect instances.
    for OPENCONNECT_PID in $(list_all_openconnect_pids); do
        [ -n "$PID" ] && [ "$OPENCONNECT_PID" = "$PID" ] && continue
        graceful_stop_openconnect_pid "$OPENCONNECT_PID"
    done

    rm -f -- "$PID_FILE"
    post_disconnect_dns_cleanup

else
    usage
    exit 1
fi
