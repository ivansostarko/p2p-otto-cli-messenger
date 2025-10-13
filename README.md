# OTTO P2P Chat — System Installer

This bundle installs the OTTO P2P Chat as:
- a **system application** (`/usr/local/bin/p2pchat` interactive CLI), and
- a **systemd service** (`p2p-otto-chat.service`) for headless operation.

Supported: **Ubuntu/Debian**, **CentOS/RHEL** (systemd-based).

## Files
- `install.sh` — installer
- `uninstall.sh` — uninstaller
- `p2p-otto-chat.service` — systemd unit
- `p2pchat.env.example` — config template copied to `/etc/p2p-otto-chat/p2pchat.env`
- `app/` — application sources (Python)

## Install
```bash
sudo bash install.sh
sudo nano /etc/p2p-otto-chat/p2pchat.env   # set MODE=host|client, PORT, NICKNAME, HOST (if client)
sudo systemctl start p2p-otto-chat
systemctl status p2p-otto-chat
journalctl -u p2p-otto-chat -f
```

The interactive CLI (manual use) stays available:
```bash
p2pchat
```

## Service config (`/etc/p2p-otto-chat/p2pchat.env`)
```ini
P2PCHAT_MODE=host           # host or client
P2PCHAT_PORT=5000           # port to listen/connect
P2PCHAT_NICKNAME=service    # nickname
# P2PCHAT_HOST=192.168.1.50  # required in client mode
```

## Uninstall
```bash
sudo bash uninstall.sh
```

## Notes
- The service uses a dedicated system user `p2pchat` and installs to `/opt/p2p-otto-chat`.
- Dependencies are installed via apt (Ubuntu/Debian) or yum/dnf (CentOS/RHEL). Python packages are isolated in a venv.
- For production, consider adding an authenticated identity layer (e.g., Ed25519 signatures) on top of the ephemeral X25519 handshake.
