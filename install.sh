#!/usr/bin/env bash
set -euo pipefail

APP_NAME="p2p-otto-chat"
APP_USER="p2pchat"
APP_DIR="/opt/${APP_NAME}"
ENV_DIR="/etc/${APP_NAME}"
SERVICE_FILE="/etc/systemd/system/${APP_NAME}.service"

echo "[1/6] Detecting OS and installing prerequisites..."

if [ -f /etc/os-release ]; then
  . /etc/os-release
else
  echo "Cannot detect OS (missing /etc/os-release)"; exit 1
fi

install_deps_debian() {
  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    python3 python3-venv python3-pip python3-dev build-essential \
    libffi-dev libssl-dev gcc
}

install_deps_rhel() {
  if command -v dnf >/dev/null 2>&1; then PM=dnf; else PM=yum; fi
  $PM -y install python3 python3-venv python3-pip python3-devel gcc make \
    libffi-devel openssl-devel
}

case "${ID_LIKE:-}${ID:-}" in
  *debian*|*ubuntu*|debian|ubuntu) install_deps_debian ;;
  *rhel*|*centos*|*fedora*|rhel|centos|fedora) install_deps_rhel ;;
  *)
    echo "Unsupported OS family. Try on Ubuntu/Debian/CentOS/RHEL."; exit 1 ;;
esac

echo "[2/6] Creating system user and directories..."
id -u "${APP_USER}" >/dev/null 2>&1 || useradd --system --home "${APP_DIR}" --shell /usr/sbin/nologin "${APP_USER}"

mkdir -p "${APP_DIR}"
mkdir -p "${ENV_DIR}"
chown -R "${APP_USER}:${APP_USER}" "${APP_DIR}"

echo "[3/6] Copying application files..."
# The installer expects to be run from the folder containing 'app/' etc.
cp -f app/otto.py "${APP_DIR}/"
cp -f app/chat.py "${APP_DIR}/"
cp -f app/service_runner.py "${APP_DIR}/"
cp -f p2p-otto-chat.service "${SERVICE_FILE}"
cp -f p2pchat.env.example "${ENV_DIR}/p2pchat.env"
chmod 640 "${ENV_DIR}/p2pchat.env"
chown -R "${APP_USER}:${APP_USER}" "${ENV_DIR}"

echo "[4/6] Setting up virtualenv and installing Python deps..."
python3 -m venv "${APP_DIR}/venv"
"${APP_DIR}/venv/bin/pip" install --upgrade pip setuptools wheel
cp -f app/requirements.txt "${APP_DIR}/requirements.txt"
"${APP_DIR}/venv/bin/pip" install -r "${APP_DIR}/requirements.txt"

echo "[5/6] Installing CLI wrapper..."
cp -f p2pchat /usr/local/bin/p2pchat
chmod 755 /usr/local/bin/p2pchat

echo "[6/6] Enabling systemd service..."
systemctl daemon-reload
systemctl enable "${APP_NAME}.service"

echo "============================================"
echo "Installed ${APP_NAME}."
echo "Config file: ${ENV_DIR}/p2pchat.env"
echo "Edit MODE/PORT/NICKNAME (and HOST for client)."
echo "Start service:    sudo systemctl start ${APP_NAME}"
echo "Check status:     systemctl status ${APP_NAME}"
echo "Logs (journal):   journalctl -u ${APP_NAME} -f"
echo ""
echo "Interactive CLI (manual): run 'p2pchat'"
echo "============================================"
