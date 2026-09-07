#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(
    cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &&
    pwd
)"

source "${SCRIPT_DIR}/common.sh"

require_root

MODE="mock"
HOST=""
PORT="8080"
SERIAL_PORT="/dev/ttyUSB0"
SERIAL_BAUD="115200"

usage() {
    printf '%s\n' \
        "Usage:" \
        "  sudo ./deploy/install.sh [options]" \
        "" \
        "Options:" \
        "  --mode mock|hardware" \
        "  --host ADDRESS" \
        "  --port PORT" \
        "  --serial-port PATH" \
        "  --serial-baud RATE" \
        "  -h, --help"
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --mode)
            MODE="${2:?Missing value for --mode}"
            shift 2
            ;;
        --host)
            HOST="${2:?Missing value for --host}"
            shift 2
            ;;
        --port)
            PORT="${2:?Missing value for --port}"
            shift 2
            ;;
        --serial-port)
            SERIAL_PORT="${2:?Missing value for --serial-port}"
            shift 2
            ;;
        --serial-baud)
            SERIAL_BAUD="${2:?Missing value for --serial-baud}"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "ERROR: Unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [ "${MODE}" != "mock" ] &&
   [ "${MODE}" != "hardware" ]
then
    echo "ERROR: --mode must be mock or hardware" >&2
    exit 2
fi

if [ -z "${HOST}" ]; then
    if [ "${MODE}" = "mock" ]; then
        HOST="127.0.0.1"
    else
        HOST="0.0.0.0"
    fi
fi

if [ "$(uname -s)" != "Linux" ]; then
    echo "ERROR: This installer must run on Linux." >&2
    exit 1
fi

for command_name in \
    python3 \
    rsync \
    curl \
    tar \
    sha256sum \
    systemctl \
    systemd-analyze \
    useradd \
    usermod \
    groupadd \
    getent \
    install
do
    require_command "${command_name}"
done

if [ ! -d /run/systemd/system ]; then
    echo "ERROR: systemd is not running." >&2
    exit 1
fi

if [ ! -f "${SOURCE_DIR}/app.py" ]; then
    echo "ERROR: Gateway source not found at ${SOURCE_DIR}" >&2
    exit 1
fi

if [ ! -f "${SOURCE_DIR}/requirements.txt" ]; then
    echo "ERROR: requirements.txt is missing" >&2
    exit 1
fi

CONFIG_TEMPLATE="${SOURCE_DIR}/deploy/config.${MODE}.json"

if [ ! -f "${CONFIG_TEMPLATE}" ]; then
    echo "ERROR: Missing configuration template:" >&2
    echo "${CONFIG_TEMPLATE}" >&2
    exit 1
fi

python3 \
    "${SOURCE_DIR}/deploy/validate-environment.py" \
    "${GATEWAY_ENV_FILE}"

printf '\n=== SOURCE VALIDATION ===\n'

python3 \
    "${SOURCE_DIR}/deploy/validate-config.py" \
    "${CONFIG_TEMPLATE}"

VALIDATION_TEMP_DIR="$(mktemp -d)"

cleanup_validation_temp() {
    rm -rf "${VALIDATION_TEMP_DIR}"
}

trap cleanup_validation_temp EXIT

PYTHONPYCACHEPREFIX="${VALIDATION_TEMP_DIR}/pycache" \
python3 -m py_compile \
    "${SOURCE_DIR}/app.py" \
    "${SOURCE_DIR}/operator_token.py" \
    "${SOURCE_DIR}/deploy/validate-environment.py" \
    "${SOURCE_DIR}/tests/test_keepalive.py" \
    "${SOURCE_DIR}/tests/test_live_gateway.py" \
    "${SOURCE_DIR}/tests/test_live_authorization.py" \
    "${SOURCE_DIR}/tests/test_mitigation_api.py" \
    "${SOURCE_DIR}/tests/test_operator_authorization.py" \
    "${SOURCE_DIR}/tests/test_deployment.py" \
    "${SOURCE_DIR}/tests/test_safe_boot.py" \
    "${SOURCE_DIR}/tests/test_serial_transactions.py" \
    "${SOURCE_DIR}/tools/run_performance_trials.py"

echo "PASS: Gateway Python syntax"

if ! python3 -m venv \
    "${VALIDATION_TEMP_DIR}/venv" >/dev/null 2>&1
then
    echo "ERROR: Python virtual environments are unavailable." >&2
    echo "Install the operating system python3-venv package." >&2
    exit 1
fi

cleanup_validation_temp
trap - EXIT

if ! getent group dialout >/dev/null 2>&1; then
    echo "ERROR: Required serial-access group does not exist: dialout" >&2
    exit 1
fi

chown root:root "${GATEWAY_ENV_FILE}"
chmod 0600 "${GATEWAY_ENV_FILE}"

python3 \
    "${SOURCE_DIR}/deploy/validate-environment.py" \
    "${GATEWAY_ENV_FILE}" \
    --require-owner-uid 0 \
    --require-owner-gid 0 \
    --require-mode 0600

if ! getent group "${SERVICE_GROUP}" >/dev/null 2>&1; then
    groupadd --system "${SERVICE_GROUP}"
fi

if ! id "${SERVICE_USER}" >/dev/null 2>&1; then
    useradd \
        --system \
        --gid "${SERVICE_GROUP}" \
        --no-create-home \
        --home-dir /nonexistent \
        --shell /usr/sbin/nologin \
        "${SERVICE_USER}"
else
    usermod \
        --gid "${SERVICE_GROUP}" \
        "${SERVICE_USER}"
fi

usermod \
    --append \
    --groups dialout \
    "${SERVICE_USER}"

mkdir -p \
    "${INSTALL_ROOT}" \
    "${BACKUP_ROOT}"

BACKUP_PATH=""

if [ -f "${APP_DIR}/app.py" ]; then
    BACKUP_PATH="${BACKUP_ROOT}/$(utc_timestamp)_before_install"

    mkdir -p \
        "${BACKUP_PATH}/gateway"

    rsync -a \
        --exclude='venv/' \
        --exclude='.venv/' \
        --exclude='data/' \
        --exclude='evidence/' \
        --exclude='__pycache__/' \
        --exclude='*.pyc' \
        --exclude='.DS_Store' \
        "${APP_DIR}/" \
        "${BACKUP_PATH}/gateway/"

    if [ -d "${APP_DIR}/data" ]; then
        tar -czf \
            "${BACKUP_PATH}/runtime-data.tar.gz" \
            -C "${APP_DIR}" \
            data
    fi

    if [ -f "${UNIT_PATH}" ]; then
        cp \
            "${UNIT_PATH}" \
            "${BACKUP_PATH}/${SERVICE_NAME}"
    fi

    {
        echo "created_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "source=${APP_DIR}"
        echo "service=${SERVICE_NAME}"
        echo "reason=automatic_pre_install_backup"
    } > "${BACKUP_PATH}/metadata.txt"

    (
        cd "${BACKUP_PATH}"

        find . \
            -type f \
            ! -name SHA256SUMS.txt \
            -print0 |
        sort -z |
        xargs -0 sha256sum \
            > SHA256SUMS.txt
    )

    echo "Backup created: ${BACKUP_PATH}"
fi

if systemctl cat \
    "${SERVICE_NAME}" >/dev/null 2>&1
then
    systemctl stop \
        "${SERVICE_NAME}" || true
fi

mkdir -p \
    "${APP_DIR}" \
    "${APP_DIR}/data"

rsync -a \
    --delete \
    --exclude='venv/' \
    --exclude='.venv/' \
    --exclude='config.json' \
    --exclude='data/' \
    --exclude='data_before_*/' \
    --exclude='evidence/' \
    --exclude='__pycache__/' \
    --exclude='*.pyc' \
    --exclude='.DS_Store' \
    --exclude='app.py.pre_*' \
    "${SOURCE_DIR}/" \
    "${APP_DIR}/"

if [ ! -x "${APP_DIR}/venv/bin/python" ]; then
    python3 -m venv \
        "${APP_DIR}/venv"
fi

"${APP_DIR}/venv/bin/python" \
    -m pip install \
    --disable-pip-version-check \
    -r "${APP_DIR}/requirements.txt"

cp \
    "${APP_DIR}/deploy/config.${MODE}.json" \
    "${APP_DIR}/config.json"

"${APP_DIR}/venv/bin/python" - \
    "${APP_DIR}/config.json" \
    "${HOST}" \
    "${PORT}" \
    "${SERIAL_PORT}" \
    "${SERIAL_BAUD}" <<'PYCONFIG'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
config = json.loads(
    path.read_text(encoding="utf-8")
)

config["host"] = sys.argv[2]
config["port"] = int(sys.argv[3])
config["serial_port"] = sys.argv[4]
config["serial_baud"] = int(sys.argv[5])
config["safe_boot_locked"] = True

path.write_text(
    json.dumps(config, indent=2) + "\n",
    encoding="utf-8",
)
PYCONFIG

"${APP_DIR}/venv/bin/python" \
    "${APP_DIR}/deploy/validate-config.py" \
    "${APP_DIR}/config.json"

install \
    -m 0644 \
    "${APP_DIR}/deploy/sentinel-gateway.service" \
    "${UNIT_PATH}"

chown -R \
    root:root \
    "${APP_DIR}"

chmod -R \
    a+rX \
    "${APP_DIR}"

mkdir -p \
    "${APP_DIR}/data"

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

chmod \
    0640 \
    "${APP_DIR}/config.json"

systemd-analyze verify \
    "${UNIT_PATH}"

systemctl daemon-reload

systemctl enable --now \
    "${SERVICE_NAME}"

sleep 3

"${APP_DIR}/deploy/health-check.sh" \
    --require-locked

printf '\nINSTALLATION PASSED\n'
printf 'Mode: %s\n' "${MODE}"
printf 'Application: %s\n' "${APP_DIR}"
printf 'Configuration: %s\n' "${APP_DIR}/config.json"
printf 'Service: %s\n' "${SERVICE_NAME}"

if [ -n "${BACKUP_PATH}" ]; then
    printf 'Previous deployment backup: %s\n' \
        "${BACKUP_PATH}"
fi
