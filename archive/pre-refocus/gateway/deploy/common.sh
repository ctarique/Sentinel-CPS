#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="sentinel-gateway.service"
SERVICE_USER="sentinel"
SERVICE_GROUP="sentinel"

INSTALL_ROOT="/opt/sentinel-cps"
APP_DIR="${INSTALL_ROOT}/gateway"
BACKUP_ROOT="${INSTALL_ROOT}/backups"

UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}"
GATEWAY_ENV_FILE="/etc/sentinel-cps/gateway.env"

SCRIPT_DIR="$(
    cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &&
    pwd
)"

SOURCE_DIR="$(
    cd -- "${SCRIPT_DIR}/.." &&
    pwd
)"

require_root() {
    if [ "${EUID}" -ne 0 ]; then
        echo "ERROR: Run this command with sudo or as root." >&2
        exit 1
    fi
}

require_command() {
    local command_name="$1"

    if ! command -v "${command_name}" >/dev/null 2>&1; then
        echo "ERROR: Required command not found: ${command_name}" >&2
        exit 1
    fi
}

utc_timestamp() {
    date -u +%Y%m%d_%H%M%S
}
