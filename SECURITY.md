# Security Policy

## Known Security Concern: Local Privilege Escalation

### Unrestricted OpenConnect Flag Forwarding

To support a wide variety of VPN configurations, `vpn-tray` allows users to specify custom OpenConnect flags in their connection profiles. The unprivileged GUI application passes these flags to the privileged helper script (`vpn-tray-helper.sh`), which executes `openconnect` as root.

While the helper script passes these arguments safely via `argv` (mitigating direct shell injection), it does not currently filter or validate the flags passed to OpenConnect. 

**Security Impact:**
Because OpenConnect may support flags that allow executing external scripts (e.g., `--script`) or reading/writing arbitrary files, a malicious local user could potentially use these flags to execute arbitrary commands as root. Therefore, granting a user `sudo` access to `vpn-tray-helper.sh` could effectively be equivalent to granting them unrestricted `sudo` access.

**Deployment Recommendation:**
Only grant `sudo` access for `vpn-tray-helper.sh` to users who are already trusted with full root access on the system. Do not use this tool as a security boundary to restrict a user's administrative privileges.

**Future Mitigation:**
We are open to issue reports and pull requests that address this, such as:
1. Implementing a strict allowlist of known-safe OpenConnect flags in the helper script.
2. Explicitly blocking known-dangerous flags (e.g., `--script`).

If you identify specific OpenConnect flags that pose a risk, please open an issue so they can be documented or blocked.
