#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(
    cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &&
    pwd
)"

TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TEMP_DIR}"' EXIT

echo
echo "=== SHELL SYNTAX ==="

for script in \
    common.sh \
    install.sh \
    health-check.sh \
    backup.sh \
    rollback.sh \
    test-bundle.sh
do
    bash -n "${SCRIPT_DIR}/${script}"
    echo "PASS: ${script}"
done

echo
echo "=== PYTHON SYNTAX ==="

PYTHONPYCACHEPREFIX="${TEMP_DIR}/pycache" \
python3 -m py_compile \
    "${SCRIPT_DIR}/../operator_token.py" \
    "${SCRIPT_DIR}/validate-config.py" \
    "${SCRIPT_DIR}/validate-environment.py"

echo "PASS: deployment Python"

echo
echo "=== ENVIRONMENT CONTRACT TESTS ==="

PYTHONPYCACHEPREFIX="${TEMP_DIR}/pycache" \
python3 -m unittest discover \
    -s "${SCRIPT_DIR}/../tests" \
    -p 'test_deployment.py' \
    -v

echo
echo "=== MOCK CONFIGURATION ==="

python3 \
    "${SCRIPT_DIR}/validate-config.py" \
    "${SCRIPT_DIR}/config.mock.json"

echo
echo "=== HARDWARE CONFIGURATION ==="

python3 \
    "${SCRIPT_DIR}/validate-config.py" \
    "${SCRIPT_DIR}/config.hardware.json"

echo
echo "=== NEGATIVE CONFIGURATION TEST ==="

python3 - \
    "${SCRIPT_DIR}/config.mock.json" \
    "${TEMP_DIR}/invalid.json" <<'PY'
import json
import sys
from pathlib import Path

source = Path(sys.argv[1])
destination = Path(sys.argv[2])

config = json.loads(
    source.read_text(encoding="utf-8")
)

config["safe_boot_locked"] = False

destination.write_text(
    json.dumps(config, indent=2) + "\n",
    encoding="utf-8",
)
PY

if python3 \
    "${SCRIPT_DIR}/validate-config.py" \
    "${TEMP_DIR}/invalid.json" \
    >/dev/null 2>&1
then
    echo "FAIL: unsafe configuration was accepted"
    exit 1
fi

echo "PASS: unsafe configuration rejected"

echo
echo "=== TRANSACTION TIMING CONFIGURATION TESTS ==="

python3 - \
    "${SCRIPT_DIR}/config.mock.json" \
    "${TEMP_DIR}/invalid-ack-timeout.json" \
    "${TEMP_DIR}/invalid-mock-delay.json" <<'PY'
import json
import sys
from pathlib import Path

source = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))

invalid_ack_timeout = dict(source)
invalid_ack_timeout["serial_ack_timeout_ms"] = 0
Path(sys.argv[2]).write_text(
    json.dumps(invalid_ack_timeout, indent=2) + "\n",
    encoding="utf-8",
)

invalid_mock_delay = dict(source)
invalid_mock_delay["mock_ack_delay_ms"] = -1
Path(sys.argv[3]).write_text(
    json.dumps(invalid_mock_delay, indent=2) + "\n",
    encoding="utf-8",
)
PY

for invalid_config in \
    "${TEMP_DIR}/invalid-ack-timeout.json" \
    "${TEMP_DIR}/invalid-mock-delay.json"
do
    if python3 \
        "${SCRIPT_DIR}/validate-config.py" \
        "${invalid_config}" \
        >/dev/null 2>&1
    then
        echo "FAIL: invalid transaction timing was accepted"
        exit 1
    fi
done

echo "PASS: invalid transaction timing rejected"

echo
echo "=== KEEPALIVE CONFIGURATION TESTS ==="

python3 - \
    "${SCRIPT_DIR}/config.mock.json" \
    "${TEMP_DIR}" <<'PY'
import json
import sys
from pathlib import Path

source = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
destination = Path(sys.argv[2])

invalid_values = (0, -1, 7000, 9000, True)
for index, value in enumerate(invalid_values):
    invalid = dict(source)
    invalid["keepalive_interval_ms"] = value
    (destination / f"invalid-keepalive-{index}.json").write_text(
        json.dumps(invalid, indent=2) + "\n",
        encoding="utf-8",
    )

invalid_enabled = dict(source)
invalid_enabled["keepalive_enabled"] = "true"
(destination / "invalid-keepalive-enabled.json").write_text(
    json.dumps(invalid_enabled, indent=2) + "\n",
    encoding="utf-8",
)
PY

for invalid_config in \
    "${TEMP_DIR}"/invalid-keepalive-*.json \
    "${TEMP_DIR}/invalid-keepalive-enabled.json"
do
    if python3 \
        "${SCRIPT_DIR}/validate-config.py" \
        "${invalid_config}" \
        >/dev/null 2>&1
    then
        echo "FAIL: invalid keepalive configuration was accepted"
        exit 1
    fi
done

echo "PASS: invalid keepalive configuration rejected"

echo
echo "=== MITIGATION CONFIGURATION TESTS ==="

python3 - \
    "${SCRIPT_DIR}/config.mock.json" \
    "${TEMP_DIR}" <<'PY'
import json
import sys
from pathlib import Path

source = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
destination = Path(sys.argv[2])

invalid_values = {
    "enabled-type": ("mitigation_api_enabled", "false"),
    "loopback-false": ("mitigation_loopback_only", False),
    "loopback-type": ("mitigation_loopback_only", "true"),
    "cache-zero": ("mitigation_idempotency_cache_size", 0),
    "cache-high": ("mitigation_idempotency_cache_size", 1025),
    "cache-bool": ("mitigation_idempotency_cache_size", True),
}
for name, (key, value) in invalid_values.items():
    invalid = dict(source)
    invalid[key] = value
    (destination / f"invalid-mitigation-{name}.json").write_text(
        json.dumps(invalid, indent=2) + "\n",
        encoding="utf-8",
    )
PY

for invalid_config in \
    "${TEMP_DIR}"/invalid-mitigation-*.json
do
    if python3 \
        "${SCRIPT_DIR}/validate-config.py" \
        "${invalid_config}" \
        >/dev/null 2>&1
    then
        echo "FAIL: invalid mitigation configuration was accepted"
        exit 1
    fi
done

echo "PASS: invalid mitigation configuration rejected"

echo
echo "=== PLACEHOLDER CHECK ==="

if grep -R \
    --exclude='test-bundle.sh' \
    -E '<USERNAME>|<PI_USER>' \
    "${SCRIPT_DIR}" >/dev/null 2>&1
then
    echo "FAIL: unresolved username placeholder"
    exit 1
fi

echo "PASS: no unresolved user placeholders"

echo
echo "=== SHELL VARIABLE EXPANSIONS ==="

python3 - "${SCRIPT_DIR}" <<'PYEXPANSIONS'
from pathlib import Path
import re
import sys

deploy = Path(sys.argv[1])
pattern = re.compile(r"\$\{\s*\n")

failures = []

for path in sorted(deploy.glob("*.sh")):
    if pattern.search(path.read_text(encoding="utf-8")):
        failures.append(path.name)

if failures:
    raise SystemExit(
        "FAIL: multiline shell-variable expansion in: "
        + ", ".join(failures)
    )

print("PASS: shell-variable expansions are runtime-safe")
PYEXPANSIONS

echo
echo "=== SERVICE FILE ==="

grep -q '^User=sentinel$' \
    "${SCRIPT_DIR}/sentinel-gateway.service"

grep -q '^Group=sentinel$' \
    "${SCRIPT_DIR}/sentinel-gateway.service"

grep -q '^Restart=on-failure$' \
    "${SCRIPT_DIR}/sentinel-gateway.service"

grep -q '^EnvironmentFile=/etc/sentinel-cps/gateway.env$' \
    "${SCRIPT_DIR}/sentinel-gateway.service"

grep -q '^ProtectSystem=strict$' \
    "${SCRIPT_DIR}/sentinel-gateway.service"

grep -q \
    '^ReadWritePaths=/opt/sentinel-cps/gateway/data$' \
    "${SCRIPT_DIR}/sentinel-gateway.service"

echo "PASS: service account and hardening settings"

echo
echo "=== DEPLOYMENT POLICY ==="

grep -q 'safe_boot_locked' \
    "${SCRIPT_DIR}/install.sh"

grep -q 'GATEWAY_ENV_FILE' \
    "${SCRIPT_DIR}/install.sh"

grep -q '0600' \
    "${SCRIPT_DIR}/install.sh"

grep -q 'chown root:root "${GATEWAY_ENV_FILE}"' \
    "${SCRIPT_DIR}/install.sh"

grep -q 'SENTINEL_OPERATOR_TOKEN is required' \
    "${SCRIPT_DIR}/../app.py"

if grep -Eq '^[[:space:]]*SENTINEL_OPERATOR_TOKEN=' \
    "${SCRIPT_DIR}/gateway.env.example"
then
    echo "FAIL: operator example contains an active assignment"
    exit 1
fi

grep -Fq "python3 -c 'import secrets; print(secrets.token_hex(32))'" \
    "${SCRIPT_DIR}/gateway.env.example"

if python3 \
    "${SCRIPT_DIR}/validate-environment.py" \
    "${SCRIPT_DIR}/gateway.env.example" \
    >/dev/null 2>&1
then
    echo "FAIL: operator example was accepted as deployable"
    exit 1
fi

grep -q -- '--require-locked' \
    "${SCRIPT_DIR}/health-check.sh"

grep -q 'SHA256SUMS.txt' \
    "${SCRIPT_DIR}/backup.sh"

grep -q -- '! -name SHA256SUMS.txt' \
    "${SCRIPT_DIR}/install.sh"

grep -q -- '! -name SHA256SUMS.txt' \
    "${SCRIPT_DIR}/backup.sh"

grep -q 'PRE_ROLLBACK_BACKUP' \
    "${SCRIPT_DIR}/rollback.sh"

grep -q -- '--require-locked' \
    "${SCRIPT_DIR}/rollback.sh"

grep -q 'Runtime data directory was preserved' \
    "${SCRIPT_DIR}/rollback.sh"

echo "PASS: installation, backup, and rollback policies"

echo
echo "DEPLOYMENT WORKFLOW STATIC TESTS PASSED"
