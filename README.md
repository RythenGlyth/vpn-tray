# vpn-tray

A Linux system tray app for OpenConnect VPN with user-level UX and a least-privilege privileged helper.

## Features

- Tray menu with:
  - Connect / Disconnect
  - Emergency Reset (stopping all openconnect instances)
  - Connection profile switching
  - Settings dialog
- Multiple VPN connection profiles (name, server, user)
- Network-aware auto-reconnect (listens to NetworkManager `StateChanged` via `dbus-monitor`)
  - Per-connection auto-reconnect toggle
- Password + OTP secret storage through Python `keyring` backend
- TOTP generation with `oathtool`
- OpenConnect custom flags per connection
  - Default: `--useragent=AnyConnect --no-external-auth`
- Least-privilege architecture:
  - UI app runs as user
  - Privileged actions delegated to `vpn-tray-helper.sh` via restricted `sudoers`
- Disconnect/reset DNS cleanup:
  - `resolvectl revert`
  - `resolvectl flush-caches`
  - `nmcli general reload`

## Install

From repository root:

```bash
./install.sh
```

Optional installer flags:

- `--user <name>`
- `--runtime-dir <path>`
- `--pid-filename <name>`
- `--lock-file <path>`
- `--update` (forces user service restart after install)

## Update

```bash
./install.sh --update
```

## Uninstall

```bash
./uninstall.sh
```

## Runtime layout

- Launcher: `/usr/bin/vpn-tray`
- App: `/usr/lib/vpn-tray/vpn-tray.py`
- Helper: `/usr/lib/vpn-tray/vpn-tray-helper.sh`
- User service: `~/.config/systemd/user/vpn-tray.service`
- Profiles: `~/.config/vpn-tray/connections.json`
- Sudo policy: `/etc/sudoers.d/vpn-tray`

## Requirements

- Linux desktop environment with tray support (StatusNotifier/AppIndicator or legacy XEmbed system tray)
- `openconnect`
- `oathtool`
- `dbus-monitor` (for auto-reconnect monitor)
- Python 3 + `PyQt6` + `keyring` (with Qt6 runtime libraries available)
- systemd user session
- sudo + `visudo`

## Security Note

### Custom OpenConnect Flags & Privilege Escalation

This application allows users to define custom OpenConnect flags in their connection profiles. These flags are passed directly to the privileged helper script (`vpn-tray-helper.sh`), which runs as root.

While arguments are passed safely via `argv` (preventing standard shell injection), OpenConnect itself may have flags (such as `--script`) that allow arbitrary code execution or file manipulation. Because the helper script does not currently validate or restrict these flags, **any user granted sudo access to run `vpn-tray-helper.sh` should be considered to have full root access to the system.**

This design is intentional to ensure compatibility across diverse VPN setups, but it represents a known local privilege escalation vector. If you discover specific OpenConnect flags that can be exploited, issue reports are welcome.

See [SECURITY.md](SECURITY.md) for more details.

## Troubleshooting

- Service status:

```bash
systemctl --user status vpn-tray.service
```

- If keyring backend is missing, install `python-keyring` in the Python environment used by the service.
- If auto-reconnect is inactive, verify `dbus-monitor` is installed.

## License

MIT. See [LICENSE](LICENSE).
