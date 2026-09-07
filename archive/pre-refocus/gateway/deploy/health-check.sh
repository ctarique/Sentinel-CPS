#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(
    cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &&
    pwd
)"

source "${SCRIPT_DIR}/common.sh"

REQUIRE_LOCKED=0
REQUIRE_CONNECTED=0

usage() {
    printf '%s\n' \
        "Usage:" \
        "  ./health-check.sh [options]" \
        "" \
        "Options:" \
        "  --require-locked" \
        "  --require-connected" \
        "  -h, --help"
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --require-locked)
            REQUIRE_LOCKED=1
            shift
            ;;
        --require-connected)
            REQUIRE_CONNECTED=1
            shift
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

for command_name in \
    curl \
    python3 \
    systemctl \
    ss
do
    require_command "${command_name}"
done

CONFIG_PATH="${APP_DIR}/config.json"

if [ ! -f "${CONFIG_PATH}" ]; then
    echo "FAIL: Configuration not found:" >&2
    echo "${CONFIG_PATH}" >&2
    exit 1
fi

if [ ! -x "${APP_DIR}/venv/bin/python" ]; then
    echo "FAIL: Gateway virtual environment is missing" >&2
    exit 1
fi

printf '\n=== CONFIGURATION ===\n'

"${APP_DIR}/venv/bin/python" \
    "${APP_DIR}/deploy/validate-config.py" \
    "${CONFIG_PATH}"

printf '\n=== SYSTEMD SERVICE ===\n'

if ! systemctl is-enabled \
    "${SERVICE_NAME}" >/dev/null 2>&1
then
    echo "FAIL: ${SERVICE_NAME} is not enabled" >&2
    exit 1
fi

echo "PASS: service enabled"

if ! systemctl is-active \
    "${SERVICE_NAME}" >/dev/null 2>&1
then
    echo "FAIL: ${SERVICE_NAME} is not active" >&2

    systemctl status \
        "${SERVICE_NAME}" \
        --no-pager \
        -l || true

    exit 1
fi

echo "PASS: service active"

read -r REQUEST_HOST PORT MODE SERIAL_PORT KEEPALIVE_ENABLED KEEPALIVE_INTERVAL_MS MITIGATION_ENABLED MITIGATION_LOOPBACK_ONLY <<EOF
$(
    python3 - "${CONFIG_PATH}" <<'PYCONFIG'
import json
import sys

with open(
    sys.argv[1],
    encoding="utf-8",
) as handle:
    config = json.load(handle)

host = config["host"]

if host in {"0.0.0.0", "::"}:
    request_host = "127.0.0.1"
else:
    request_host = host

mode = (
    "mock"
    if config["mock_serial"]
    else "hardware"
)

print(
    request_host,
    config["port"],
    mode,
    config["serial_port"],
    str(config["keepalive_enabled"]).lower(),
    config["keepalive_interval_ms"],
    str(config["mitigation_api_enabled"]).lower(),
    str(config["mitigation_loopback_only"]).lower(),
)
PYCONFIG
)
EOF

printf '\n=== API HEALTH ===\n'

HEALTH_JSON="$(
    curl \
        --fail \
        --silent \
        --show-error \
        --max-time 5 \
        "http://${REQUEST_HOST}:${PORT}/api/health"
)"

python3 - \
    "${REQUIRE_LOCKED}" \
    "${REQUIRE_CONNECTED}" \
    "${MODE}" \
    "${KEEPALIVE_ENABLED}" \
    "${KEEPALIVE_INTERVAL_MS}" \
    "${MITIGATION_ENABLED}" \
    "${MITIGATION_LOOPBACK_ONLY}" \
    "${HEALTH_JSON}" <<'PYHEALTH'
import json
import sys

require_locked = bool(int(sys.argv[1]))
require_connected = bool(int(sys.argv[2]))
mode = sys.argv[3]
keepalive_enabled = sys.argv[4] == "true"
keepalive_interval_ms = int(sys.argv[5])
mitigation_enabled = sys.argv[6] == "true"
mitigation_loopback_only = sys.argv[7] == "true"
health = json.loads(sys.argv[8])

if health.get("status") != "ok":
    raise SystemExit(
        "FAIL: health status is not ok"
    )

expected_keepalive = {
    "keepalive_enabled": keepalive_enabled,
    "keepalive_interval_ms": keepalive_interval_ms,
}
for key, value in expected_keepalive.items():
    observed = health.get(key)
    if observed != value:
        raise SystemExit(
            "FAIL: "
            f"{key} expected {value!r}, "
            f"observed {observed!r}"
        )

expected_mitigation = {
    "mitigation_api_enabled": mitigation_enabled,
    "mitigation_loopback_only": mitigation_loopback_only,
}
for key, value in expected_mitigation.items():
    observed = health.get(key)
    if observed != value:
        raise SystemExit(
            "FAIL: "
            f"{key} expected {value!r}, "
            f"observed {observed!r}"
        )

if mitigation_enabled and not health.get("mitigation_api_ready", False):
    raise SystemExit("FAIL: enabled mitigation API is not ready")

if require_locked:
    expected = {
        "gateway_locked": True,
        "safe_boot_locked": True,
        "vehicle_state": "LOCKED",
    }

    for key, value in expected.items():
        observed = health.get(key)

        if observed != value:
            raise SystemExit(
                "FAIL: "
                f"{key} expected {value!r}, "
                f"observed {observed!r}"
            )

if require_connected and not health.get(
    "connected",
    False,
):
    raise SystemExit(
        "FAIL: serial connection is not established"
    )

print(json.dumps(health, indent=2))
print(
    "PASS: API health"
    f" mode={mode}"
    f" connected={health.get('connected')}"
)
PYHEALTH

printf '\n=== LISTENING PORT ===\n'

if ! ss -ltn |
    grep -Eq ":${PORT}[[:space:]]"
then
    echo "FAIL: TCP port ${PORT} is not listening" >&2
    exit 1
fi

echo "PASS: TCP port ${PORT} is listening"

if [ "${MODE}" = "hardware" ]; then
    printf '\n=== SERIAL DEVICE ===\n'

    if [ -e "${SERIAL_PORT}" ]; then
        echo "PASS: serial device exists: ${SERIAL_PORT}"
    elif [ "${REQUIRE_CONNECTED}" -eq 1 ]; then
        echo "FAIL: serial device is missing:" >&2
        echo "${SERIAL_PORT}" >&2
        exit 1
    else
        echo "WARN: serial device is not present:"
        echo "${SERIAL_PORT}"
    fi
fi

printf '\nHEALTH CHECK PASSED\n'
