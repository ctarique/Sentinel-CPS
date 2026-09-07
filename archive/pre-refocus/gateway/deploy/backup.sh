#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(
    cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &&
    pwd
)"

source "${SCRIPT_DIR}/common.sh"

require_root

QUIET=0

if [ "${1:-}" = "--quiet" ]; then
    QUIET=1
elif [ -n "${1:-}" ]; then
    echo "Usage: sudo $0 [--quiet]" >&2
    exit 2
fi

for command_name in \
    rsync \
    tar \
    sha256sum \
    systemctl \
    python3 \
    find \
    sort \
    xargs
do
    require_command "${command_name}"
done

if [ ! -f "${APP_DIR}/app.py" ]; then
    echo "ERROR: No installed Gateway found at ${APP_DIR}" >&2
    exit 1
fi

if [ ! -f "${APP_DIR}/config.json" ]; then
    echo "ERROR: Installed Gateway configuration is missing" >&2
    exit 1
fi

DESTINATION="${BACKUP_ROOT}/$(utc_timestamp)_$$"

mkdir -p "${DESTINATION}/gateway"

rsync -a \
    --exclude='venv/' \
    --exclude='.venv/' \
    --exclude='data/' \
    --exclude='data_before_*/' \
    --exclude='evidence/' \
    --exclude='__pycache__/' \
    --exclude='*.pyc' \
    --exclude='.DS_Store' \
    --exclude='app.py.pre_*' \
    "${APP_DIR}/" \
    "${DESTINATION}/gateway/"

if [ -d "${APP_DIR}/data" ]; then
    tar -czf \
        "${DESTINATION}/runtime-data.tar.gz" \
        -C "${APP_DIR}" \
        data
fi

if [ -f "${UNIT_PATH}" ]; then
    cp \
        "${UNIT_PATH}" \
        "${DESTINATION}/${SERVICE_NAME}"
fi

GATEWAY_MODE="$(
    python3 - "${APP_DIR}/config.json" <<'PYMODE'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    config = json.load(handle)

print("mock" if config["mock_serial"] else "hardware")
PYMODE
)"

{
    echo "created_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "source=${APP_DIR}"
    echo "service=${SERVICE_NAME}"
    echo "gateway_mode=${GATEWAY_MODE}"
    echo "service_active=$(
        systemctl is-active "${SERVICE_NAME}" 2>/dev/null ||
        true
    )"
    echo "service_enabled=$(
        systemctl is-enabled "${SERVICE_NAME}" 2>/dev/null ||
        true
    )"
} > "${DESTINATION}/metadata.txt"

(
    cd "${DESTINATION}"

    find . \
        -type f \
        ! -name SHA256SUMS.txt \
        -print0 |
    sort -z |
    xargs -0 sha256sum \
        > SHA256SUMS.txt
)

if [ "${QUIET}" -eq 0 ]; then
    echo
    echo "BACKUP CREATED"
    echo "Path: ${DESTINATION}"
    echo "Manifest: ${DESTINATION}/SHA256SUMS.txt"
fi

printf '%s\n' "${DESTINATION}"
