#!/usr/bin/env bash
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${VENV_DIR:-$APP_DIR/.venv}"
SERVICE_NAME="${SERVICE_NAME:-testbuddy}"
APP_USER="${APP_USER:-$(id -un)}"
APP_GROUP="${APP_GROUP:-$(id -gn)}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
TESTBUDDY_HOST="${TESTBUDDY_HOST:-0.0.0.0}"
TESTBUDDY_PORT="${TESTBUDDY_PORT:-5001}"

if ! command -v systemctl >/dev/null 2>&1; then
    echo "systemctl is required to install the ${SERVICE_NAME} service." >&2
    exit 1
fi

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    echo "Python interpreter not found: $PYTHON_BIN" >&2
    exit 1
fi

if ! id "$APP_USER" >/dev/null 2>&1; then
    echo "User does not exist: $APP_USER" >&2
    exit 1
fi

if ! getent group "$APP_GROUP" >/dev/null 2>&1; then
    echo "Group does not exist: $APP_GROUP" >&2
    exit 1
fi

if [[ $EUID -eq 0 ]]; then
    SUDO=()
else
    if ! command -v sudo >/dev/null 2>&1; then
        echo "sudo is required when not running as root." >&2
        exit 1
    fi
    SUDO=(sudo)
fi

echo "Deploying Test Buddy from $APP_DIR"
echo "Using service name: $SERVICE_NAME"
echo "Using app user/group: $APP_USER:$APP_GROUP"
echo "Using bind address: $TESTBUDDY_HOST:$TESTBUDDY_PORT"

if [[ ! -d "$VENV_DIR" ]]; then
    "$PYTHON_BIN" -m venv "$VENV_DIR"
    echo "Created virtual environment at $VENV_DIR"
fi

"$VENV_DIR/bin/pip" install --upgrade pip
"$VENV_DIR/bin/pip" install -r "$APP_DIR/requirements.txt"

UNIT_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
TMP_UNIT="$(mktemp)"
trap 'rm -f "$TMP_UNIT"' EXIT

cat >"$TMP_UNIT" <<EOF
[Unit]
Description=Test Buddy dashboard
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$APP_USER
Group=$APP_GROUP
WorkingDirectory=$APP_DIR
Environment=PYTHONUNBUFFERED=1
Environment=TESTBUDDY_HOST=$TESTBUDDY_HOST
Environment=TESTBUDDY_PORT=$TESTBUDDY_PORT
ExecStart=$VENV_DIR/bin/python $APP_DIR/app.py
Restart=always
RestartSec=5
KillSignal=SIGINT

[Install]
WantedBy=multi-user.target
EOF

"${SUDO[@]}" install -m 0644 "$TMP_UNIT" "$UNIT_FILE"
"${SUDO[@]}" systemctl daemon-reload
"${SUDO[@]}" systemctl enable --now "$SERVICE_NAME"
"${SUDO[@]}" systemctl restart "$SERVICE_NAME"

echo
echo "Service status:"
"${SUDO[@]}" systemctl --no-pager --full status "$SERVICE_NAME" || true

echo
echo "Deployment complete."
echo "Useful commands:"
echo "  sudo systemctl restart $SERVICE_NAME"
echo "  sudo systemctl status $SERVICE_NAME"
echo "  sudo journalctl -u $SERVICE_NAME -f"
