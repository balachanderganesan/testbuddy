#!/usr/bin/env bash
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${ENV_FILE:-$APP_DIR/.env}"
VENV_DIR="${VENV_DIR:-$APP_DIR/.venv}"
SERVICE_NAME="${SERVICE_NAME:-testbuddy}"
APP_USER="${APP_USER:-$(id -un)}"
APP_GROUP="${APP_GROUP:-$(id -gn)}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

dotenv_get() {
    local key="$1"
    local file="$2"
    local line value

    [[ -f "$file" ]] || return 1

    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"
        [[ -z "$line" || "${line:0:1}" == "#" ]] && continue
        [[ "$line" == export\ * ]] && line="${line#export }"
        [[ "$line" == "$key="* ]] || continue
        value="${line#*=}"
        value="${value#"${value%%[![:space:]]*}"}"
        value="${value%"${value##*[![:space:]]}"}"
        if [[ ${#value} -ge 2 ]]; then
            if [[ "${value:0:1}" == '"' && "${value: -1}" == '"' ]]; then
                value="${value:1:${#value}-2}"
            elif [[ "${value:0:1}" == "'" && "${value: -1}" == "'" ]]; then
                value="${value:1:${#value}-2}"
            fi
        fi
        printf '%s\n' "$value"
        return 0
    done < "$file"

    return 1
}

systemd_escape() {
    local value="$1"
    value="${value//\\/\\\\}"
    value="${value// /\\x20}"
    value="${value//$'\t'/\\x09}"
    printf '%s' "$value"
}

TESTBUDDY_HOST="${TESTBUDDY_HOST:-$(dotenv_get TESTBUDDY_HOST "$ENV_FILE" 2>/dev/null || true)}"
TESTBUDDY_PORT="${TESTBUDDY_PORT:-$(dotenv_get TESTBUDDY_PORT "$ENV_FILE" 2>/dev/null || true)}"
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
if [[ -f "$ENV_FILE" ]]; then
    echo "Using env file: $ENV_FILE"
else
    echo "Env file not found: $ENV_FILE (defaults and existing environment will be used)"
fi

if [[ ! -x "$VENV_DIR/bin/python" ]]; then
    if [[ -d "$VENV_DIR" ]]; then
        echo "Existing virtual environment at $VENV_DIR is incomplete; recreating it"
        rm -rf "$VENV_DIR"
    fi
    "$PYTHON_BIN" -m venv "$VENV_DIR"
    echo "Created virtual environment at $VENV_DIR"
fi

if [[ ! -x "$VENV_DIR/bin/pip" ]]; then
    echo "pip is missing from $VENV_DIR; bootstrapping it with ensurepip"
    "$VENV_DIR/bin/python" -m ensurepip --upgrade
fi

"$VENV_DIR/bin/python" -m pip install --upgrade pip
"$VENV_DIR/bin/python" -m pip install -r "$APP_DIR/requirements.txt"

UNIT_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
TMP_UNIT="$(mktemp)"
trap 'rm -f "$TMP_UNIT"' EXIT
ESC_APP_DIR="$(systemd_escape "$APP_DIR")"
ESC_ENV_FILE="$(systemd_escape "$ENV_FILE")"
ESC_PYTHON="$(systemd_escape "$VENV_DIR/bin/python")"
ESC_APP="$(systemd_escape "$APP_DIR/app.py")"

cat >"$TMP_UNIT" <<EOF
[Unit]
Description=Test Buddy dashboard
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$APP_USER
Group=$APP_GROUP
Environment="PYTHONUNBUFFERED=1"
Environment="TESTBUDDY_DOTENV_PATH=$ESC_ENV_FILE"
WorkingDirectory=$ESC_APP_DIR
ExecStart=$ESC_PYTHON $ESC_APP
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
