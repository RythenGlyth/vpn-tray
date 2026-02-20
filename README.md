# vpn-tray

[![Release](https://img.shields.io/github/v/release/RythenGlyth/vpn-tray?sort=semver)](https://github.com/RythenGlyth/vpn-tray/releases)
[![Release build](https://img.shields.io/github/actions/workflow/status/RythenGlyth/vpn-tray/release.yml?label=release%20build)](https://github.com/RythenGlyth/vpn-tray/actions/workflows/release.yml)
[![License](https://img.shields.io/github/license/RythenGlyth/vpn-tray)](LICENSE)

A Linux system tray app for OpenConnect VPN with a user-friendly workflow and a least-privilege helper.

## Quickstart

```bash
git clone https://github.com/RythenGlyth/vpn-tray.git
cd vpn-tray
./install.sh
```

Then open the tray app and add your first connection in **Settings**.

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

## Requirements

- Linux desktop environment with tray support (StatusNotifier/AppIndicator or legacy XEmbed system tray)
- `openconnect`
- `oathtool`
- `dbus-monitor` (for auto-reconnect monitor)
- Python 3 + `PyQt6` + `keyring` (with Qt6 runtime libraries available)
- systemd user session
- sudo + `visudo`

## Installation

### Arch Linux

**Option A: Install from AUR (Recommended)**

```bash
yay -S vpn-tray
```
*(Or use your preferred AUR helper)*

**Option B: Build manually**

Download `PKGBUILD` and `vpn-tray.install` from the [latest release](https://github.com/RythenGlyth/vpn-tray/releases) into a directory, then run:

```bash
makepkg -si
```

### Debian / Ubuntu

Download the latest `.deb` package from [releases](https://github.com/RythenGlyth/vpn-tray/releases) and install:

```bash
sudo apt install ./vpn-tray_<version>_all.deb
```

### From Source

You can install directly from the repository or from the source tarball.

**Method 1: Git Clone**

```bash
git clone https://github.com/RythenGlyth/vpn-tray.git
cd vpn-tray
./install.sh
```

**Method 2: Source Tarball**

Download `vpn-tray-<version>.tar.gz` from [releases](https://github.com/RythenGlyth/vpn-tray/releases).

```bash
tar -xzf vpn-tray-<version>.tar.gz
cd vpn-tray-<version>
./install.sh
```

#### Installer Options

The `./install.sh` script accepts the following arguments:

- `--user <name>`: Install for a specific user (defaults to current)
- `--runtime-dir <path>`: Override runtime directory
- `--pid-filename <name>`: Override PID filename
- `--lock-file <path>`: Override lock file path
- `--update`: Force restart of the user service after install


## Updating

```bash
./install.sh --update
```

## Uninstalling

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

- Journal log:

  ```
  journalctl --user -u vpn-tray
  ```

- If keyring backend is missing, install `python-keyring` in the Python environment used by the service.
- If auto-reconnect is inactive, verify `dbus-monitor` is installed.

## License

MIT. See [LICENSE](LICENSE).
