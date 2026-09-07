#!/usr/bin/env bash
# val01_port_probe.sh
# Safe client-side reachability tester for Sentinel-CPS VAL-01.

set -u

TARGET="${1:-}"
PORTS=("${@:2}")
if [ -z "$TARGET" ]; then
  echo "Usage: ./val01_port_probe.sh <GATEWAY_IP_OR_HOSTNAME> [ports...]"
  echo "Default ports: 22 8080"
  exit 1
fi

if [ ${#PORTS[@]} -eq 0 ]; then
  PORTS=(22 8080)
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="$PACKAGE_DIR/evidence/VAL-01_Access_Control/endpoint_port_tests"
mkdir -p "$OUT_DIR"
TIMESTAMP="$(date +"%Y%m%d_%H%M%S")"
SAFE_TARGET="$(echo "$TARGET" | tr -c 'A-Za-z0-9._-' '_')"
OUT_TXT="$OUT_DIR/port_probe_${SAFE_TARGET}_${TIMESTAMP}.txt"
OUT_CSV="$OUT_DIR/port_probe_${SAFE_TARGET}_${TIMESTAMP}.csv"

echo "timestamp,target,port,test_type,result,details" > "$OUT_CSV"

log_csv() {
  local port="$1"
  local test_type="$2"
  local result="$3"
  local details="$4"
  printf '"%s","%s","%s","%s","%s","%s"\n' "$(date --iso-8601=seconds 2>/dev/null || date)" "$TARGET" "$port" "$test_type" "$result" "$details" >> "$OUT_CSV"
}

{
  echo "--- Sentinel-CPS Port Probe v0.1.1 ---"
  echo "Target: $TARGET"
  echo "Timestamp: $(date)"
  echo "Output CSV: $OUT_CSV"
  echo "Note: This is a non-destructive reachability test."
  echo "----------------------------------------"

  for port in "${PORTS[@]}"; do
    echo
    echo "[*] TCP Port $port reachability"
    if command -v nc >/dev/null 2>&1; then
      if nc -vz -w 2 "$TARGET" "$port" >/tmp/val01_nc_probe.$$ 2>&1; then
        echo "PASS: Port $port reachable"
        log_csv "$port" "tcp_connect" "PASS" "reachable via nc"
      else
        detail="$(tr '\n' ' ' < /tmp/val01_nc_probe.$$ | sed 's/"/'\''/g')"
        echo "FAIL_OR_FILTERED: Port $port not reachable via nc"
        log_csv "$port" "tcp_connect" "FAIL_OR_FILTERED" "$detail"
      fi
      rm -f /tmp/val01_nc_probe.$$
    else
      if timeout 2 bash -c "</dev/tcp/$TARGET/$port" >/dev/null 2>&1; then
        echo "PASS: Port $port reachable"
        log_csv "$port" "tcp_connect" "PASS" "reachable via bash devtcp"
      else
        echo "FAIL_OR_FILTERED: Port $port not reachable"
        log_csv "$port" "tcp_connect" "FAIL_OR_FILTERED" "nc unavailable; bash devtcp failed"
      fi
    fi
  done

  echo
  echo "[*] Port 8080 health endpoint"
  if command -v curl >/dev/null 2>&1; then
    HTTP_BODY="$(curl -sS --max-time 3 "http://$TARGET:8080/api/health" 2>/tmp/val01_curl_probe.$$ || true)"
    CURL_STATUS=$?
    if echo "$HTTP_BODY" | grep -qi 'mode\|status\|vehicle_state\|mock\|hardware'; then
      echo "PASS: /api/health returned expected-looking response"
      echo "Response: $HTTP_BODY"
      log_csv "8080" "http_health" "PASS" "expected-looking /api/health response"
    else
      detail="$(cat /tmp/val01_curl_probe.$$ 2>/dev/null | tr '\n' ' ' | sed 's/"/'\''/g')"
      echo "INCONCLUSIVE_OR_FAIL: /api/health did not return expected response"
      echo "Response: $HTTP_BODY"
      log_csv "8080" "http_health" "INCONCLUSIVE_OR_FAIL" "$detail"
    fi
    rm -f /tmp/val01_curl_probe.$$
  else
    echo "INCONCLUSIVE: curl not installed"
    log_csv "8080" "http_health" "INCONCLUSIVE" "curl not installed"
  fi

  echo
  echo "[*] SSH non-interactive auth check"
  echo "This attempts a non-interactive SSH connection with password auth disabled. It should not prompt."
  if command -v ssh >/dev/null 2>&1; then
    ssh -o BatchMode=yes -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o ConnectTimeout=3 "probe_test@$TARGET" exit >/tmp/val01_ssh_probe.$$ 2>&1
    RES=$?
    detail="$(tr '\n' ' ' < /tmp/val01_ssh_probe.$$ | sed 's/"/'\''/g')"
    if [ $RES -eq 255 ]; then
      echo "PASS_OR_EXPECTED_REJECTION: SSH did not allow interactive password auth for probe_test."
      log_csv "22" "ssh_batchmode" "PASS_OR_EXPECTED_REJECTION" "$detail"
    else
      echo "INCONCLUSIVE: SSH command exited with code $RES. Review manually."
      log_csv "22" "ssh_batchmode" "INCONCLUSIVE" "exit_code=$RES $detail"
    fi
    rm -f /tmp/val01_ssh_probe.$$
  else
    echo "INCONCLUSIVE: ssh client not installed"
    log_csv "22" "ssh_batchmode" "INCONCLUSIVE" "ssh client not installed"
  fi

  echo
  echo "[*] mDNS note: Port 5353 uses UDP multicast and is not validated by this TCP probe."
  echo "[*] TXT output: $OUT_TXT"
  echo "[*] CSV output: $OUT_CSV"
} | tee "$OUT_TXT"
