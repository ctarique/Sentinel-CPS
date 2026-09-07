# Sentinel-CPS eBPF/BCC Trace MVP Package v0.1.1

This package prepares a minimal, read-only observability workflow for the Sentinel-CPS Raspberry Pi Gateway. It focuses on host-level syscall metadata around the serial chokepoint used by the Gateway-to-ESP32 Hub path, normally `/dev/ttyUSB0` at 115200 baud.

## What this package does

- Checks whether the Raspberry Pi/Linux Gateway is ready for BCC-based tracing.
- Traces `read` and `write` syscall metadata using BCC tracepoints.
- Performs best-effort user-space file descriptor resolution through `/proc/<pid>/fd/<fd>`.
- Writes structured CSV traces for serial read/write activity.
- Summarizes trace output into simple count and byte metrics.
- Correlates Gateway `actions.csv` entries with nearby eBPF serial activity.
- Supports evidence collection for VAL-04 Gateway Observability and prepares later VAL-05 STOP/mitigation correlation.

## What this package does not do

- It does not modify kernel settings, firewall rules, serial data, Gateway code, or service configuration.
- It does not capture serial payload contents by default.
- It does not guarantee detection or provide complete visibility.
- It does not validate ESP-NOW/CCMP, physical vehicle navigation, or AI anomaly detection by itself.

## Basic workflow

Run these commands from `observability-ebpf/tools/` on the Raspberry Pi Gateway.

```bash
bash check_bcc_environment.sh

sudo python3 trace_serial_syscalls_bcc.py \
  --device /dev/ttyUSB0 \
  --duration 60

python3 summarize_serial_trace.py \
  --input ../evidence/VAL-04_Observability/ebpf_traces/<serial_trace_file>.csv

python3 correlate_gateway_logs.py \
  --actions ../../gateway/data/actions.csv \
  --telemetry ../../gateway/data/telemetry.csv \
  --ebpf ../evidence/VAL-04_Observability/ebpf_traces/<serial_trace_file>.csv
```

Raw trace outputs may contain usernames, process names, paths, device names, timestamps, and lab environment details. Keep raw outputs in private OneDrive unless sanitized.

## Thesis mapping

This package collects evidence for:

- VAL-04 Gateway Observability
- SR-O1 eBPF/BCC telemetry preparation
- SR-O2 anomaly-detection preparation through structured metadata
- Later VAL-05 correlation between application commands and serial activity

Use careful wording in the thesis: this package supports evidence collection and trace correlation. It should not be described as absolute visibility, guaranteed detection, or a complete security proof.
