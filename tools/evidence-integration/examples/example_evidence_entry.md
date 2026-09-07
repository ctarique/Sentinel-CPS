# Example Evidence Entry: EVID-VAL01-012

**Evidence ID:** EVID-VAL01-012

**Date collected:** YYYY-MM-DD

**Validation target:** VAL-01 Access Control and Gateway Hardening

**Artifact type:** Terminal output

**Filename:** `val01_systemctl_status_YYYYMMDD.txt`

**Private path:** `OneDrive/Sentinel-CPS_Evidence_Master/VAL-01_Access_Control/terminal_logs/`

**Public redacted path:** `GitHub/sanitized-evidence-examples/VAL-01/` if needed

## Description

Output of `systemctl status sentinel-gateway.service --no-pager` showing the Sentinel-CPS Gateway running as a native systemd service on the Raspberry Pi Gateway.

## Thesis use

Supports Chapter 4 implementation discussion of the bare-metal Gateway service and Chapter 5 VAL-01/VAL-04 evidence that the Gateway service was active during validation.

## Privacy and sanitization

The raw file may contain usernames, hostnames, process IDs, timestamps, or paths. Save the original in OneDrive. Redact usernames, hostnames, and environment-specific details before using it in public GitHub material.

## Safe claim supported

“During the validation run, the Gateway process was active as a native systemd service on the Raspberry Pi.”

## Limitation

This evidence only shows service status at the time of capture. It does not prove long-term availability or security by itself.
