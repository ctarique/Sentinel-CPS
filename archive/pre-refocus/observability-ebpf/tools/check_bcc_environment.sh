#!/usr/bin/env bash
# Sentinel-CPS eBPF/BCC environment checker v0.1.1
# Read-only. Does not install or modify anything.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="$BASE_DIR/evidence/VAL-04_Observability/environment_checks"
mkdir -p "$OUT_DIR"
OUT_FILE="$OUT_DIR/bcc_environment_$(date +%Y%m%d_%H%M%S).txt"

log() {
  echo "$*" | tee -a "$OUT_FILE"
}

run_capture() {
  local label="$1"
  shift
  log ""
  log "## $label"
  "$@" >> "$OUT_FILE" 2>&1 || log "[WARN] Command failed or unavailable: $*"
}

log "=== Sentinel-CPS eBPF/BCC Environment Checker v0.1.1 ==="
log "Generated: $(date -Is)"
log "Output: $OUT_FILE"

run_capture "System info" uname -a
run_capture "Kernel release" uname -r
run_capture "Python version" python3 --version

log ""
log "## BCC package check"
if command -v dpkg >/dev/null 2>&1; then
  dpkg -l | grep -E 'bpfcc|bcc' >> "$OUT_FILE" 2>&1 || log "[WARN] No bpfcc/bcc packages found through dpkg."
elif command -v rpm >/dev/null 2>&1; then
  rpm -qa | grep -E 'bcc|bpf' >> "$OUT_FILE" 2>&1 || log "[WARN] No bcc/bpf packages found through rpm."
else
  log "[INFO] Package manager check skipped; dpkg/rpm not found."
fi

log ""
log "## Python BCC import"
if python3 - <<'PY' >> "$OUT_FILE" 2>&1
from bcc import BPF
print('OK: from bcc import BPF succeeded')
PY
then
  log "[OK] Python BCC import succeeded."
else
  log "[WARN] Python BCC import failed. Suggested packages may include python3-bpfcc and bpfcc-tools, depending on OS."
fi

log ""
log "## tracefs/debugfs"
if mount | grep -E 'debugfs|tracefs' >> "$OUT_FILE" 2>&1; then
  log "[OK] tracefs/debugfs appears mounted."
else
  log "[WARN] tracefs/debugfs not found in mount output."
fi

log ""
log "## Privilege check"
if [ "${EUID}" -eq 0 ]; then
  log "[OK] Running as root."
elif sudo -n true >/dev/null 2>&1; then
  log "[OK] sudo appears available without prompting."
else
  log "[INFO] Tracing likely requires sudo/root. This script did not prompt for credentials."
fi

log ""
log "## Target serial device"
if [ -e /dev/ttyUSB0 ]; then
  ls -l /dev/ttyUSB0 >> "$OUT_FILE" 2>&1
  log "[OK] /dev/ttyUSB0 exists."
else
  log "[WARN] /dev/ttyUSB0 not found. Try: ls /dev/ttyUSB* /dev/ttyACM* 2>/dev/null"
fi

log ""
log "## Alternative serial devices"
ls -l /dev/ttyUSB* /dev/ttyACM* >> "$OUT_FILE" 2>&1 || log "[INFO] No ttyUSB/ttyACM devices listed."

log ""
log "## sentinel-gateway.service status"
if systemctl status sentinel-gateway.service --no-pager >> "$OUT_FILE" 2>&1; then
  log "[OK] sentinel-gateway.service status collected."
else
  log "[WARN] sentinel-gateway.service not found or not running."
fi

log ""
log "## app.py process check"
ps aux | grep -E '[a]pp\.py|[s]entinel' >> "$OUT_FILE" 2>&1 || log "[INFO] No obvious app.py/sentinel process found."

log ""
log "=== Check complete ==="
log "Saved to: $OUT_FILE"
