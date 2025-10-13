#!/usr/bin/env bash
set -euo pipefail

APP_NAME="p2p-otto-chat"
APP_USER="p2pchat"
APP_DIR="/opt/${APP_NAME}"
ENV_DIR="/etc/${APP_NAME}"
SERVICE_FILE="/etc/systemd/system/${APP_NAME}.service"

echo "[*] Stopping service (if running)..."
systemctl stop "${APP_NAME}.service" || true
systemctl disable "${APP_NAME}.service" || true
systemctl daemon-reload || true

echo "[*] Removing files..."
rm -f "/usr/local/bin/p2pchat" || true
rm -f "${SERVICE_FILE}" || true
rm -rf "${APP_DIR}" || true
rm -rf "${ENV_DIR}" || true

echo "[*] (Optional) Remove system user ${APP_USER}? y/N"
read -r ans
if [[ "${ans:-N}" =~ ^[Yy]$ ]]; then
  userdel -r "${APP_USER}" || true
fi

echo "Uninstalled."
