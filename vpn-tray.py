#!/usr/bin/env python3
import sys
import os
import shutil
import atexit
import fcntl
import time
import re
import json
import hashlib
import subprocess
import threading
from collections import deque
try:
    import keyring
    from keyring.errors import KeyringError
except Exception:  # pragma: no cover - optional runtime dependency
    keyring = None

    class KeyringError(Exception):
        pass

from PyQt6.QtWidgets import (
    QApplication,
    QSystemTrayIcon,
    QMenu,
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QListWidget,
    QMessageBox,
    QCheckBox,
)
from PyQt6.QtGui import QIcon, QAction
from PyQt6.QtCore import pyqtSignal, QObject

class SignalHandler(QObject):
    connected_signal = pyqtSignal()
    connect_failed_signal = pyqtSignal(str)
    nm_state_changed_signal = pyqtSignal(int)


KEYRING_SERVICE = "vpn-tray"
KEYRING_PASSWORD_SUFFIX = "password"
KEYRING_OTP_SUFFIX = "otp_secret"


class ConnectionEditDialog(QDialog):
    def __init__(self, parent=None, initial=None):
        super().__init__(parent)
        self.setWindowTitle("Connection")

        initial = initial or {}
        self.name_edit = QLineEdit(initial.get("name", ""))
        self.server_edit = QLineEdit(initial.get("server", ""))
        self.user_edit = QLineEdit(initial.get("user", ""))
        self.auto_reconnect_check = QCheckBox("Enable auto-reconnect for this connection")
        self.auto_reconnect_check.setChecked(bool(initial.get("auto_reconnect", True)))

        layout = QVBoxLayout()

        layout.addWidget(QLabel("Name"))
        layout.addWidget(self.name_edit)
        layout.addWidget(QLabel("VPN Server"))
        layout.addWidget(self.server_edit)
        layout.addWidget(QLabel("VPN User"))
        layout.addWidget(self.user_edit)
        layout.addWidget(self.auto_reconnect_check)

        buttons = QHBoxLayout()
        save_btn = QPushButton("Save")
        cancel_btn = QPushButton("Cancel")
        save_btn.clicked.connect(self._on_save)
        cancel_btn.clicked.connect(self.reject)
        buttons.addWidget(save_btn)
        buttons.addWidget(cancel_btn)
        layout.addLayout(buttons)

        self.setLayout(layout)

    def _on_save(self):
        if not self.name_edit.text().strip() or not self.server_edit.text().strip() or not self.user_edit.text().strip():
            QMessageBox.warning(self, "Invalid input", "Name, VPN Server, and VPN User are required.")
            return
        self.accept()

    def connection(self):
        return {
            "name": self.name_edit.text().strip(),
            "server": self.server_edit.text().strip(),
            "user": self.user_edit.text().strip(),
            "auto_reconnect": self.auto_reconnect_check.isChecked(),
        }


class SecretPromptDialog(QDialog):
    def __init__(self, connection_name, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Store VPN Secrets")

        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.otp_secret_edit = QLineEdit()
        self.otp_secret_edit.setEchoMode(QLineEdit.EchoMode.Password)

        layout = QVBoxLayout()
        layout.addWidget(QLabel(f"No stored secrets found for '{connection_name}'."))
        layout.addWidget(QLabel("VPN Password"))
        layout.addWidget(self.password_edit)
        layout.addWidget(QLabel("OTP Secret (TOTP seed)"))
        layout.addWidget(self.otp_secret_edit)

        buttons = QHBoxLayout()
        save_btn = QPushButton("Save")
        cancel_btn = QPushButton("Cancel")
        save_btn.clicked.connect(self._on_save)
        cancel_btn.clicked.connect(self.reject)
        buttons.addWidget(save_btn)
        buttons.addWidget(cancel_btn)
        layout.addLayout(buttons)

        self.setLayout(layout)

    def _on_save(self):
        if not self.password_edit.text().strip() or not self.otp_secret_edit.text().strip():
            QMessageBox.warning(self, "Invalid input", "Password and OTP secret are required.")
            return
        self.accept()

    def secrets(self):
        return self.password_edit.text().strip(), self.otp_secret_edit.text().strip()


class ConnectionSettingsDialog(QDialog):
    def __init__(self, parent=None, profiles=None, active_name=None):
        super().__init__(parent)
        self.setWindowTitle("VPN Connections")
        self._profiles = [dict(p) for p in (profiles or [])]
        self._active_name = active_name

        layout = QVBoxLayout()
        self.list_widget = QListWidget()
        layout.addWidget(self.list_widget)

        row = QHBoxLayout()
        self.add_btn = QPushButton("Add")
        self.edit_btn = QPushButton("Edit")
        self.remove_btn = QPushButton("Remove")
        self.active_btn = QPushButton("Set Active")
        row.addWidget(self.add_btn)
        row.addWidget(self.edit_btn)
        row.addWidget(self.remove_btn)
        row.addWidget(self.active_btn)
        layout.addLayout(row)

        bottom = QHBoxLayout()
        save_btn = QPushButton("Save")
        cancel_btn = QPushButton("Cancel")
        bottom.addWidget(save_btn)
        bottom.addWidget(cancel_btn)
        layout.addLayout(bottom)

        self.setLayout(layout)

        self.add_btn.clicked.connect(self._add_profile)
        self.edit_btn.clicked.connect(self._edit_profile)
        self.remove_btn.clicked.connect(self._remove_profile)
        self.active_btn.clicked.connect(self._set_active_selected)
        save_btn.clicked.connect(self._on_save)
        cancel_btn.clicked.connect(self.reject)

        self._refresh_list()

    def _display_label(self, p):
        active = " [active]" if p.get("name") == self._active_name else ""
        return f"{p.get('name', '')}: {p.get('user', '')}@{p.get('server', '')}{active}"

    def _refresh_list(self):
        self.list_widget.clear()
        for p in self._profiles:
            self.list_widget.addItem(self._display_label(p))

    def _selected_index(self):
        row = self.list_widget.currentRow()
        return row if row >= 0 else None

    def _name_exists(self, name, skip_index=None):
        for i, p in enumerate(self._profiles):
            if skip_index is not None and i == skip_index:
                continue
            if p.get("name") == name:
                return True
        return False

    def _add_profile(self):
        dlg = ConnectionEditDialog(self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        conn = dlg.connection()
        if self._name_exists(conn["name"]):
            QMessageBox.warning(self, "Duplicate name", "A connection with this name already exists.")
            return
        self._profiles.append(conn)
        if not self._active_name:
            self._active_name = conn["name"]
        self._refresh_list()

    def _edit_profile(self):
        idx = self._selected_index()
        if idx is None:
            return
        current = self._profiles[idx]
        dlg = ConnectionEditDialog(self, current)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        updated = dlg.connection()
        if self._name_exists(updated["name"], skip_index=idx):
            QMessageBox.warning(self, "Duplicate name", "A connection with this name already exists.")
            return
        old_name = current.get("name")
        self._profiles[idx] = updated
        if self._active_name == old_name:
            self._active_name = updated["name"]
        self._refresh_list()

    def _remove_profile(self):
        idx = self._selected_index()
        if idx is None:
            return
        removed = self._profiles.pop(idx)
        if removed.get("name") == self._active_name:
            self._active_name = self._profiles[0]["name"] if self._profiles else None
        self._refresh_list()

    def _set_active_selected(self):
        idx = self._selected_index()
        if idx is None:
            return
        self._active_name = self._profiles[idx].get("name")
        self._refresh_list()

    def _on_save(self):
        if self._profiles and not self._active_name:
            self._active_name = self._profiles[0].get("name")
        self.accept()

    def result_state(self):
        return self._profiles, self._active_name

class VPNApp:
    def __init__(self):
        self.app = QApplication(sys.argv)
        self.helper_path = os.getenv("VPN_TRAY_HELPER") or "/usr/lib/vpn-tray/vpn-tray-helper.sh"
        self.runtime_dir = os.getenv("VPN_TRAY_RUNTIME_DIR") or self._default_runtime_dir()
        self.pid_filename = os.getenv("VPN_TRAY_PID_FILENAME") or "vpn_tray.pid"
        self.pid_file = os.path.join(self.runtime_dir, self.pid_filename)
        self.lock_file = os.getenv("VPN_TRAY_LOCK_FILE") or "/tmp/vpn-tray.lock"
        self.config_dir = os.getenv("VPN_TRAY_CONFIG_DIR") or self._default_config_dir()
        self.config_file = os.path.join(self.config_dir, "connections.json")
        self.connection_profiles = []
        self.active_connection_name = None
        self.settings_dialog = None
        self.recent_err_lines = deque(maxlen=12)
        self._connected_emitted = False
        self._connect_result_lock = threading.Lock()
        self._connect_result_reported = False
        self._wants_connection = False
        self._network_was_lost_while_connected = False
        self._auto_reconnect_in_progress = False
        self._nm_last_state = None
        self._nm_monitor_proc = None

        if not self.acquire_single_instance_lock():
            print("Another vpn-tray instance is already running.", file=sys.stderr, flush=True)
            sys.exit(1)
        
        self.tray = QSystemTrayIcon()
        self.tray.setToolTip("VPN-Tray")
        self.tray.setIcon(QIcon.fromTheme("network-disconnect")) # Default to disconnected icon
        
        self.menu = QMenu()
        
        self.connect_action = QAction("Connect")
        self.connect_action.triggered.connect(self.connect_vpn)
        self.menu.addAction(self.connect_action)
        
        self.disconnect_action = QAction("Disconnect")
        self.disconnect_action.triggered.connect(self.disconnect_vpn)
        self.menu.addAction(self.disconnect_action)

        self.connection_menu = QMenu("Connections")
        self.connection_menu.aboutToShow.connect(self._refresh_connection_menu)
        self.menu.addMenu(self.connection_menu)

        self.settings_action = QAction("Settings...")
        self.settings_action.triggered.connect(self.open_settings)
        self.menu.addAction(self.settings_action)

        self.menu.addSeparator()
        
        self.reset_action = QAction("Emergency Reset")
        self.reset_action.triggered.connect(self.force_reset)
        self.menu.addAction(self.reset_action)
        
        self.menu.addSeparator()
        
        self.quit_action = QAction("Quit")
        self.quit_action.triggered.connect(self.app.quit)
        self.menu.addAction(self.quit_action)
        
        self.tray.setContextMenu(self.menu)
        self.tray.show()
        
        self.signals = SignalHandler()
        self.signals.connected_signal.connect(self.show_connected_msg)
        self.signals.connect_failed_signal.connect(self.log_error)
        self.signals.nm_state_changed_signal.connect(self._on_nm_state_changed)

        self._load_connections()
        self._refresh_connection_menu()
        self._update_connect_action_label()

        # Check state on startup
        self.check_initial_state()
        self._start_network_monitor()

    @staticmethod
    def _default_runtime_dir():
        xdg_runtime = os.getenv("XDG_RUNTIME_DIR")
        if xdg_runtime:
            return os.path.join(xdg_runtime, "vpn-tray")
        return f"/tmp/vpn-tray-{os.getuid()}"

    @staticmethod
    def _default_config_dir():
        xdg_config = os.getenv("XDG_CONFIG_HOME")
        if xdg_config:
            return os.path.join(xdg_config, "vpn-tray")
        return os.path.join(os.path.expanduser("~/.config"), "vpn-tray")

    def _normalize_profile(self, profile):
        if not isinstance(profile, dict):
            return None
        name = str(profile.get("name", "")).strip()
        server = str(profile.get("server", "")).strip()
        user = str(profile.get("user", "")).strip()
        auto_reconnect = bool(profile.get("auto_reconnect", True))
        if not name or not server or not user:
            return None
        return {"name": name, "server": server, "user": user, "auto_reconnect": auto_reconnect}

    def _load_connections(self):
        self.connection_profiles = []
        self.active_connection_name = None

        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                profiles = data.get("connections", []) if isinstance(data, dict) else []
                for p in profiles:
                    normalized = self._normalize_profile(p)
                    if normalized:
                        self.connection_profiles.append(normalized)
                active = data.get("active") if isinstance(data, dict) else None
                if isinstance(active, str):
                    self.active_connection_name = active
            except Exception:
                pass

        if self.connection_profiles and not any(p["name"] == self.active_connection_name for p in self.connection_profiles):
            self.active_connection_name = self.connection_profiles[0]["name"]

    def _save_connections(self):
        try:
            os.makedirs(self.config_dir, mode=0o700, exist_ok=True)
            with open(self.config_file, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "active": self.active_connection_name,
                        "connections": self.connection_profiles,
                    },
                    f,
                    indent=2,
                )
        except OSError as e:
            self.log_error("Failed to save connection settings.", e)

    def _active_profile(self):
        for p in self.connection_profiles:
            if p.get("name") == self.active_connection_name:
                return p
        return None

    def _refresh_connection_menu(self):
        self.connection_menu.clear()
        if not self.connection_profiles:
            no_profiles_action = QAction("No connections configured")
            no_profiles_action.setEnabled(False)
            self.connection_menu.addAction(no_profiles_action)
            self._update_connect_action_label()
            return

        for profile in self.connection_profiles:
            name = profile["name"]
            action = QAction(name)
            action.setCheckable(True)
            action.setChecked(name == self.active_connection_name)
            action.triggered.connect(lambda checked, n=name: self._set_active_connection(n))
            self.connection_menu.addAction(action)

        self._update_connect_action_label()

    def _set_active_connection(self, name):
        self.active_connection_name = name
        self._save_connections()
        self._refresh_connection_menu()

    def _update_connect_action_label(self):
        profile = self._active_profile()
        if profile:
            self.connect_action.setText(f"Connect ({profile['name']})")
        else:
            self.connect_action.setText("Connect (none)")

        if self.disconnect_action.isEnabled():
            return
        self.connect_action.setEnabled(profile is not None)

    def _active_auto_reconnect(self):
        profile = self._active_profile()
        if not profile:
            return False
        return bool(profile.get("auto_reconnect", True))

    @staticmethod
    def _connection_key_base(profile):
        raw = f"{profile.get("user", "default")}@{profile.get("server", "default")} ({profile.get("name", "default")})"
        base = re.sub(r"[^A-Za-z0-9._-]", "_", raw)
        digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:8]
        prefix = base[:40] if base else "default"
        return f"{prefix}_{digest}"

    def _secret_entry_names(self, profile):
        base = self._connection_key_base(profile)
        return f"{base}.{KEYRING_PASSWORD_SUFFIX}", f"{base}.{KEYRING_OTP_SUFFIX}"

    def _read_secret(self, entry_name):
        if keyring is None:
            return None
        try:
            value = keyring.get_password(KEYRING_SERVICE, entry_name)
        except Exception:
            return None
        return value.strip() if isinstance(value, str) and value.strip() else None

    def _write_secret(self, entry_name, value):
        if keyring is None:
            return False
        try:
            keyring.set_password(KEYRING_SERVICE, entry_name, value)
            return True
        except Exception:
            return False

    def _ensure_profile_secrets(self, profile):
        password_key, otp_key = self._secret_entry_names(profile)

        password = self._read_secret(password_key)
        otp_secret = self._read_secret(otp_key)
        if password and otp_secret:
            return password, otp_secret

        dlg = SecretPromptDialog(profile.get("name", "connection"), self.tray.contextMenu())
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return None, None

        password, otp_secret = dlg.secrets()
        if not self._write_secret(password_key, password):
            self.log_error("Failed to store VPN password in keyring.")
            return None, None
        if not self._write_secret(otp_key, otp_secret):
            self.log_error("Failed to store OTP secret in keyring.")
            return None, None
        return password, otp_secret

    def _apply_settings_from_dialog(self):
        if self.settings_dialog is None:
            return

        profiles, active = self.settings_dialog.result_state()
        self.connection_profiles = [p for p in (self._normalize_profile(x) for x in profiles) if p]
        self.active_connection_name = active
        if self.connection_profiles and not any(p["name"] == self.active_connection_name for p in self.connection_profiles):
            self.active_connection_name = self.connection_profiles[0]["name"]
        self._save_connections()
        self._refresh_connection_menu()
        self._update_connect_action_label()

    def _on_settings_finished(self, _result_code):
        if self.settings_dialog is None:
            return

        self.settings_dialog.deleteLater()
        self.settings_dialog = None

    def open_settings(self):
        if self.settings_dialog is not None and self.settings_dialog.isVisible():
            self.settings_dialog.showNormal()
            self.settings_dialog.raise_()
            self.settings_dialog.activateWindow()
            self.settings_dialog.setFocus()
            return

        self.settings_dialog = ConnectionSettingsDialog(self.tray.contextMenu(), self.connection_profiles, self.active_connection_name)
        self.settings_dialog.setModal(False)
        self.settings_dialog.accepted.connect(self._apply_settings_from_dialog)
        self.settings_dialog.finished.connect(self._on_settings_finished)
        self.settings_dialog.show()
        self.settings_dialog.raise_()
        self.settings_dialog.activateWindow()

    def acquire_single_instance_lock(self):
        """Ensures only one tray instance is active."""
        try:
            self.lock_fp = open(self.lock_file, "w")
            fcntl.flock(self.lock_fp.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.lock_fp.write(str(os.getpid()))
            self.lock_fp.flush()
            atexit.register(self.release_single_instance_lock)
            return True
        except OSError:
            return False

    def release_single_instance_lock(self):
        try:
            if hasattr(self, "lock_fp") and self.lock_fp:
                fcntl.flock(self.lock_fp.fileno(), fcntl.LOCK_UN)
                self.lock_fp.close()
        except OSError:
            pass

    @staticmethod
    def _is_pid_alive(pid):
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True

    def _read_pid_from_file(self):
        if not os.path.exists(self.pid_file):
            return None
        try:
            with open(self.pid_file, "r", encoding="utf-8") as f:
                content = f.read().strip()
            if not content.isdigit():
                return None
            return int(content)
        except OSError:
            return None

    def update_ui_state(self, is_connected):
        """Toggles menu buttons and tray icon based on connection state."""
        if is_connected:
            self.tray.setIcon(QIcon.fromTheme("network-vpn"))
            self.connect_action.setEnabled(False)
            self.disconnect_action.setEnabled(True)
        else:
            # Uses standard KDE disconnected/offline icon
            self.tray.setIcon(QIcon.fromTheme("network-disconnect")) 
            self.disconnect_action.setEnabled(False)
            self._update_connect_action_label()

    def check_initial_state(self):
        """Checks if the VPN is already running when the app starts."""
        pid = self._read_pid_from_file()
        if pid and self._is_pid_alive(pid):
            self._wants_connection = True
            self.update_ui_state(is_connected=True)
            return

        # Ghost PID file: try to clean it up silently
        if os.path.exists(self.pid_file):
            try:
                os.remove(self.pid_file)
            except OSError:
                pass
        self._wants_connection = False
        self.update_ui_state(is_connected=False)

    def show_connected_msg(self):
        self._wants_connection = True
        self._network_was_lost_while_connected = False
        self._auto_reconnect_in_progress = False
        self.update_ui_state(is_connected=True)
        profile = self._active_profile()
        if profile:
            self.tray.showMessage("VPN Connected", f"Connected via {profile['name']} ({profile['user']}@{profile['server']}).")
        else:
            self.tray.showMessage("VPN Connected", "Secure tunnel established.")

    def _start_network_monitor(self):
        if shutil.which("dbus-monitor") is None:
            print("Auto-reconnect disabled: dbus-monitor not found.", file=sys.stderr, flush=True)
            return
        threading.Thread(target=self._network_monitor_loop, daemon=True).start()

    def _network_monitor_loop(self):
        cmd = [
            "dbus-monitor",
            "--system",
            "type='signal',sender='org.freedesktop.NetworkManager',interface='org.freedesktop.NetworkManager',member='StateChanged'",
        ]
        try:
            self._nm_monitor_proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
        except Exception as e:
            print(f"Failed to start dbus-monitor: {e}", file=sys.stderr, flush=True)
            return

        for line in self._nm_monitor_proc.stdout:
            match = re.search(r"uint32\s+(\d+)", line)
            if not match:
                continue
            self.signals.nm_state_changed_signal.emit(int(match.group(1)))

    def _on_nm_state_changed(self, state):
        if state == self._nm_last_state:
            return
        self._nm_last_state = state

        is_online = state >= 50  # NM_STATE_CONNECTED_LOCAL/SITE/GLOBAL
        if not is_online:
            if self._wants_connection:
                self._network_was_lost_while_connected = True
                self._auto_reconnect_in_progress = False
                self.update_ui_state(is_connected=False)
            return

        if not self._active_auto_reconnect():
            return
        if not self._wants_connection:
            return
        if self._auto_reconnect_in_progress:
            return

        pid = self._read_pid_from_file()
        vpn_pid_alive = bool(pid and self._is_pid_alive(pid))

        # Recover either after a known network loss event, or when network is back
        # but the tracked VPN process is gone/stale.
        if not self._network_was_lost_while_connected and vpn_pid_alive:
            return

        self._auto_reconnect_in_progress = True
        self.tray.showMessage("VPN", "Network restored. Reconnecting VPN...")

        reset_result = self._run_and_capture([
            'sudo', '-n', self.helper_path, 'reset', self.pid_filename
        ])
        if reset_result.returncode != 0:
            self._auto_reconnect_in_progress = False
            hint = self._trim_stderr(reset_result.stderr)
            self.log_error(f"Auto-reconnect reset failed{': ' + hint if hint else ''}.")
            return

        self.update_ui_state(is_connected=False)
        self.connect_vpn()

    @staticmethod
    def _line_indicates_connected(log_line):
        return "Continuing in background; pid" in log_line

    @staticmethod
    def _extract_background_pid(log_line):
        match = re.search(r"Continuing in background; pid\s+(\d+)", log_line)
        if not match:
            return None
        return int(match.group(1))

    @staticmethod
    def _is_benign_stderr_line(log_line):
        text = log_line.strip().lower()
        benign_markers = (
            "please enter your username and password.",
            "password:",
            "please enter second factor",
            "response:",
            "ignoring non-forwardable exclude route",
        )
        return any(marker in text for marker in benign_markers)

    def _emit_connect_success_once(self):
        with self._connect_result_lock:
            if self._connect_result_reported:
                return
            self._connect_result_reported = True
            self._connected_emitted = True
            self._auto_reconnect_in_progress = False
        self.signals.connected_signal.emit()

    def _emit_connect_failure_once(self, message):
        with self._connect_result_lock:
            if self._connect_result_reported:
                return
            self._connect_result_reported = True
            self._auto_reconnect_in_progress = False
        self.signals.connect_failed_signal.emit(message)

    def _wait_for_vpn_pid(self, timeout_seconds=6.0):
        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            pid = self._read_pid_from_file()
            if pid and self._is_pid_alive(pid):
                return True
            time.sleep(0.2)
        return False

    def stream_logs(self, pipe, prefix, file_stream):
        for line in pipe:
            log_line = line.strip()
            print(log_line, file=file_stream, flush=True)

            if prefix == "VPN-ERR" and log_line and not self._is_benign_stderr_line(log_line):
                self.recent_err_lines.append(log_line)

            if self._line_indicates_connected(log_line) and not self._connected_emitted:
                # For --background mode this log line is authoritative for successful connection.
                pid_from_log = self._extract_background_pid(log_line)
                if pid_from_log is not None and self._is_pid_alive(pid_from_log):
                    self._emit_connect_success_once()
                elif self._wait_for_vpn_pid():
                    self._emit_connect_success_once()
                else:
                    self._emit_connect_success_once()

    def _check_dependencies(self):
        required = ["oathtool", self.helper_path]
        missing = [binary for binary in required if shutil.which(binary) is None]
        if missing:
            self.log_error(f"Missing required command(s): {', '.join(missing)}")
            return False
        if keyring is None:
            self.log_error("Missing Python dependency: keyring")
            return False
        profile = self._active_profile()
        if not profile:
            self.log_error("No VPN connection configured. Open Settings and add a connection.")
            return False
        return True

    def _tail_error_hint(self):
        return self.recent_err_lines[-1] if self.recent_err_lines else None

    def _categorize_connect_failure(self, return_code):
        hint = "\n".join(self.recent_err_lines).lower()

        if return_code in (126, 127) or "not authorized" in hint or "authentication dialog was dismissed" in hint:
            return "Authorization was cancelled or denied."
        if "auth failed" in hint or "authentication failed" in hint:
            return "VPN authentication failed (password/OTP)."
        if "resolve" in hint or "network is unreachable" in hint or "connection refused" in hint or "timed out" in hint:
            return "Network connection to VPN gateway failed."

        tail = self._tail_error_hint()
        if tail:
            return f"VPN connection failed: {tail}"
        return "VPN connection failed."

    def _monitor_connect_exit(self, proc):
        return_code = proc.wait()
        if self._connected_emitted:
            return

        # In --background mode a zero exit code means the tunnel process was spawned successfully.
        if return_code == 0:
            self._emit_connect_success_once()
            return

        self._emit_connect_failure_once(self._categorize_connect_failure(return_code))

    def log_error(self, message, exception=None):
        error_msg = message
        if exception:
            error_msg += f" Details: {exception}"
        print(error_msg, file=sys.stderr, flush=True)
        self.tray.showMessage("VPN Error", message)
        self.update_ui_state(is_connected=False)

    def _run_and_capture(self, cmd, input_text=None):
        return subprocess.run(cmd, text=True, capture_output=True, input=input_text)

    def _trim_stderr(self, text):
        if not text:
            return None
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if not lines:
            return None
        return lines[-1]

    def connect_vpn(self):
        if not self._check_dependencies():
            return

        self._wants_connection = True

        self._connected_emitted = False
        self._connect_result_reported = False
        self.recent_err_lines.clear()

        self.tray.showMessage("VPN", "Connecting...")
        self.connect_action.setEnabled(False) # Disable immediately to prevent double-clicks
        self.disconnect_action.setEnabled(False)

        profile = self._active_profile()
        if not profile:
            self.log_error("No active VPN connection configured.")
            return
        
        try:
            password, secret = self._ensure_profile_secrets(profile)
            if not password or not secret:
                return

            totp_result = self._run_and_capture(['oathtool', '--totp', '-b', secret])
            if totp_result.returncode != 0:
                hint = self._trim_stderr(totp_result.stderr)
                self.log_error(f"Failed to generate TOTP{': ' + hint if hint else ''}.")
                return
            totp = totp_result.stdout.strip()
        except Exception as e:
            self.log_error("Failed to retrieve secrets from keyring.", e)
            return

        auth_payload = f"{password}\n{totp}\n"

        vpn_server = profile["server"]
        vpn_user = profile["user"]

        cmd = [
            'sudo', '-n', self.helper_path, 'start', self.pid_filename, vpn_server, vpn_user
        ]
        
        try:
            proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        except Exception as e:
            self.log_error("Failed to start OpenConnect process.", e)
            return
        
        threading.Thread(target=self.stream_logs, args=(proc.stdout, "VPN-INFO", sys.stdout), daemon=True).start()
        threading.Thread(target=self.stream_logs, args=(proc.stderr, "VPN-ERR", sys.stderr), daemon=True).start()
        threading.Thread(target=self._monitor_connect_exit, args=(proc,), daemon=True).start()
        
        try:
            proc.stdin.write(auth_payload)
            proc.stdin.flush()
            proc.stdin.close()
        except Exception as e:
            self.log_error("Failed to pipe credentials.", e)

    def disconnect_vpn(self):
        self.tray.showMessage("VPN", "Disconnecting...")
        self.disconnect_action.setEnabled(False)
        self._wants_connection = False
        self._network_was_lost_while_connected = False
        self._auto_reconnect_in_progress = False

        try:
            stop_result = self._run_and_capture([
                'sudo', '-n', self.helper_path, 'stop', self.pid_filename
            ])
            if stop_result.returncode != 0:
                hint = self._trim_stderr(stop_result.stderr)
                self.log_error(f"Failed to stop VPN process{': ' + hint if hint else ''}.")
                return

            self.update_ui_state(is_connected=False)
            self.tray.showMessage("VPN Disconnected", "Tunnel closed successfully.")
        except Exception as e:
            self.log_error("Failed to disconnect VPN.", e)

    def force_reset(self):
        """Forcefully kills any openconnect instances and wipes the PID file."""
        self._wants_connection = False
        self._network_was_lost_while_connected = False
        self._auto_reconnect_in_progress = False
        try:
            reset_result = self._run_and_capture([
                'sudo', '-n', self.helper_path, 'reset', self.pid_filename
            ])
            if reset_result.returncode != 0:
                hint = self._trim_stderr(reset_result.stderr)
                self.log_error(f"Failed to reset VPN{': ' + hint if hint else ''}.")
                return
            self.update_ui_state(is_connected=False)
            self.tray.showMessage("VPN Reset", "VPN process forcefully terminated.")
        except Exception as e:
            self.log_error("Failed to reset VPN.", e)

if __name__ == "__main__":
    app = VPNApp()
    sys.exit(app.app.exec())