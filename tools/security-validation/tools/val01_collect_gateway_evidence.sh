#!/usr/bin/env bash
# val01_collect_gateway_evidence.sh
# Read-only Sentinel-CPS Gateway evidence collector for VAL-01.
# This script does not modify SSH, firewall, systemd, or network settings.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TIMESTAMP="$(date +"%Y%m%d_%H%M%S")"
OUT_DIR="$PACKAGE_DIR/evidence/VAL-01_Access_Control/$TIMESTAMP"
MANIFEST="$OUT_DIR/evidence_manifest.csv"

mkdir -p "$OUT_DIR"

printf '[*] Sentinel-CPS Gateway Evidence Collector\n'
printf '[*] Output directory: %s\n' "$OUT_DIR"
printf '[*] This collector is read-only. It does not apply configuration changes.\n\n'

write_meta() {
  {
    echo "collector_version=v0.1.1"
    echo "timestamp=$TIMESTAMP"
    echo "script_dir=$SCRIPT_DIR"
    echo "package_dir=$PACKAGE_DIR"
  } > "$OUT_DIR/00_collector_metadata.txt"
}

safe_run() {
  local label="$1"
  local outfile="$2"
  shift 2
  local path="$OUT_DIR/$outfile"

  printf '[+] %s -> %s\n' "$label" "$outfile"
  {
    echo "# Command: $*"
    echo "# Timestamp: $(date --iso-8601=seconds 2>/dev/null || date)"
    echo
    "$@"
  } > "$path" 2>&1

  local status=$?
  if [ $status -ne 0 ]; then
    {
      echo
      echo "# Command exited with status $status. This may be normal if the command is unavailable or permission is denied."
    } >> "$path"
  fi
}

safe_shell() {
  local label="$1"
  local outfile="$2"
  local cmd="$3"
  local path="$OUT_DIR/$outfile"

  printf '[+] %s -> %s\n' "$label" "$outfile"
  {
    echo "# Command: $cmd"
    echo "# Timestamp: $(date --iso-8601=seconds 2>/dev/null || date)"
    echo
    bash -lc "$cmd"
  } > "$path" 2>&1

  local status=$?
  if [ $status -ne 0 ]; then
    {
      echo
      echo "# Command exited with status $status. This may be normal if the command is unavailable or permission is denied."
    } >> "$path"
  fi
}

write_meta

# 1. Basic host info
safe_run "Kernel and OS" "01_uname.txt" uname -a
safe_run "Hostnamectl" "02_hostnamectl.txt" hostnamectl
safe_run "Date/time" "03_date.txt" date
safe_run "Current user" "04_whoami.txt" whoami

# 2. Network posture. These are private raw evidence.
safe_run "IP addresses" "05_ip_addr.txt" ip addr
safe_run "IP routes" "06_ip_route.txt" ip route
safe_shell "Listening ports" "07_listening_ports.txt" "ss -tulpen 2>/dev/null || ss -tuln"

# 3. Sentinel service and service inventory
safe_run "sentinel-gateway.service status" "08_sentinel_gateway_service_status.txt" systemctl status sentinel-gateway.service --no-pager
safe_run "sentinel-gateway.service journal" "09_sentinel_gateway_journal_last100.txt" journalctl -u sentinel-gateway.service -n 100 --no-pager
safe_run "Running services" "10_running_services.txt" systemctl --type=service --state=running --no-pager
safe_shell "Avahi/mDNS status" "11_avahi_status.txt" "systemctl status avahi-daemon --no-pager || echo 'avahi-daemon not active or not installed'"

# 4. SSH hardening evidence
safe_shell "SSH service status" "12_ssh_status.txt" "systemctl status ssh --no-pager || systemctl status sshd --no-pager"
safe_shell "Effective sshd config" "13_sshd_config_effective.txt" "sshd -T 2>/dev/null || sudo -n sshd -T"
safe_shell "SSH config grep" "14_ssh_config_grep.txt" "grep -RHiE '^[[:space:]]*(PasswordAuthentication|PubkeyAuthentication|PermitRootLogin|AuthorizedKeysFile|AllowUsers|AllowGroups|DenyUsers|DenyGroups|KbdInteractiveAuthentication|ChallengeResponseAuthentication)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d 2>/dev/null || true"

# Do not collect authorized_keys contents. Collect metadata only.
AUTH_META="$OUT_DIR/15_authorized_keys_metadata.txt"
{
  echo "# Authorized keys metadata only. Key contents are not collected."
  echo "# Timestamp: $(date --iso-8601=seconds 2>/dev/null || date)"
  echo
  for ak in "$HOME/.ssh/authorized_keys" /root/.ssh/authorized_keys; do
    if [ -f "$ak" ]; then
      echo "file=$ak"
      echo "line_count=$(wc -l < "$ak")"
      echo "sha256_file_hash=$(sha256sum "$ak" | awk '{print $1}')"
      echo "key_fingerprints:"
      if command -v ssh-keygen >/dev/null 2>&1; then
        # Prints public key fingerprints without printing full key material.
        ssh-keygen -lf "$ak" 2>/dev/null || echo "fingerprint extraction failed"
      else
        echo "ssh-keygen unavailable"
      fi
      echo
    else
      echo "not_found=$ak"
    fi
  done
} > "$AUTH_META" 2>&1
printf '[+] Authorized keys metadata -> 15_authorized_keys_metadata.txt\n'

# 5. Firewall posture. Read-only; non-interactive sudo only.
if command -v nft >/dev/null 2>&1; then
  safe_shell "nftables ruleset" "16_nftables_ruleset.txt" "sudo -n nft list ruleset 2>/dev/null || nft list ruleset 2>/dev/null || echo 'nftables ruleset unavailable or sudo required'"
else
  echo "nft command not found" > "$OUT_DIR/16_nftables_ruleset.txt"
fi

if command -v ufw >/dev/null 2>&1; then
  safe_shell "ufw status" "17_ufw_status.txt" "sudo -n ufw status verbose 2>/dev/null || ufw status verbose 2>/dev/null || echo 'ufw status unavailable or sudo required'"
else
  echo "ufw command not found" > "$OUT_DIR/17_ufw_status.txt"
fi

# 6. Repository private-key scan metadata from package parent if available.
safe_shell "Local sensitive filename scan" "18_sensitive_filename_scan.txt" "cd '$PACKAGE_DIR/..' 2>/dev/null && find . -path './.git' -prune -o \\( -name '.env' -o -name '*.pem' -o -name '*.key' -o -name 'id_ed25519' -o -name 'id_rsa' -o -iname '*secret*' -o -iname '*credential*' \\) -print | sort || true"

# 7. Manifest with SHA256 checksums.
printf '[+] Generating evidence manifest\n'
echo "filename,sha256_checksum,notes" > "$MANIFEST"
(
  cd "$OUT_DIR" || exit 1
  for file in *; do
    if [ -f "$file" ] && [ "$file" != "evidence_manifest.csv" ]; then
      checksum="$(sha256sum "$file" | awk '{print $1}')"
      printf '"%s","%s",""\n' "$file" "$checksum" >> "$MANIFEST"
    fi
  done
)

printf '\n[*] Evidence collection complete.\n'
printf '[*] Raw evidence folder: %s\n' "$OUT_DIR"
printf '[*] Review and copy this folder to private OneDrive. Redact before using public examples.\n'
