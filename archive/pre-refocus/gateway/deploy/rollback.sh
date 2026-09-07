#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(
    cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &&
    pwd
)"

source "${SCRIPT_DIR}/common.sh"

require_root

if [ "$#" -ne 1 ]; then
    echo "Usage: sudo $0 <backup-directory|latest>" >&2
    exit 2
fi

SELECTION="$1"

for command_name in \
    rsync \
    sha256sum \
    systemctl \
    python3 \
    find \
    sort \
    tail \
    install
do
    require_command "${command_name}"
done

if [ "${SELECTION}" = "latest" ]; then
    BACKUP_DIRECTORY="$(
        find "${BACKUP_ROOT}" \
            -mindepth 1 \
            -maxdepth 1 \
            -type d \
            -print |
        sort |
        tail -n 1
    )"
else
    BACKUP_DIRECTORY="${SELECTION}"
fi

if [ -z "${BACKUP_DIRECTORY}" ] ||
   [ ! -d "${BACKUP_DIRECTORY}" ]
then
    echo "ERROR: Backup directory not found" >&2
    exit 1
fi

if [ ! -f "${BACKUP_DIRECTORY}/gateway/app.py" ]; then
    echo "ERROR: Backup does not contain gateway/app.py" >&2
    exit 1
fi

if [ ! -f "${BACKUP_DIRECTORY}/gateway/config.json" ]; then
    echo "ERROR: Backup does not contain gateway/config.json" >&2
    exit 1
fi

if [ ! -f "${BACKUP_DIRECTORY}/SHA256SUMS.txt" ]; then
    echo "ERROR: Backup checksum manifest is missing" >&2
    exit 1
fi

echo
echo "=== VERIFY BACKUP INTEGRITY ==="

(
    cd "${BACKUP_DIRECTORY}"
    sha256sum -c SHA256SUMS.txt
)

python3 \
    "${SCRIPT_DIR}/validate-config.py" \
    "${BACKUP_DIRECTORY}/gateway/config.json"

echo
echo "=== CREATE PRE-ROLLBACK SAFETY BACKUP ==="

PRE_ROLLBACK_BACKUP="$(
    "${SCRIPT_DIR}/backup.sh" --quiet |
    tail -n 1
)"

echo "Pre-rollback backup: ${PRE_ROLLBACK_BACKUP}"

echo
echo "=== RESTORE APPLICATION ==="

systemctl stop "${SERVICE_NAME}" 2>/dev/null ||
true

rsync -a \
    --delete \
    --exclude='venv/' \
    --exclude='data/' \
    "${BACKUP_DIRECTORY}/gateway/" \
    "${APP_DIR}/"

if [ -f "${BACKUP_DIRECTORY}/${SERVICE_NAME}" ]; then
    install \
        -m 0644 \
        "${BACKUP_DIRECTORY}/${SERVICE_NAME}" \
        "${UNIT_PATH}"
fi

if [ ! -x "${APP_DIR}/venv/bin/python" ]; then
    python3 -m venv "${APP_DIR}/venv"
fi

"${APP_DIR}/venv/bin/python" \
    -m pip install \
    --disable-pip-version-check \
    -r "${APP_DIR}/requirements.txt"

python3 \
    "${APP_DIR}/deploy/validate-config.py" \
    "${APP_DIR}/config.json"

chown -R root:root "${APP_DIR}"
chmod -R a+rX "${APP_DIR}"

mkdir -p "${APP_DIR}/data"

chown -R \
    "${SERVICE_USER}:${SERVICE_GROUP}" \
    "${APP_DIR}/data"

find "${APP_DIR}/data" \
    -type d \
    -exec chmod 0750 {} +

find "${APP_DIR}/data" \
    -type f \
    -exec chmod 0640 {} +

chown \
    root:"${SERVICE_GROUP}" \
    "${APP_DIR}/config.json"

chmod 0640 "${APP_DIR}/config.json"

systemctl daemon-reload
systemctl enable --now "${SERVICE_NAME}"

sleep 3

"${APP_DIR}/deploy/health-check.sh" \
    --require-locked

echo
echo "ROLLBACK PASSED"
echo "Restored backup: ${BACKUP_DIRECTORY}"
echo "Pre-rollback safety backup: ${PRE_ROLLBACK_BACKUP}"
echo "Runtime data directory was preserved."
