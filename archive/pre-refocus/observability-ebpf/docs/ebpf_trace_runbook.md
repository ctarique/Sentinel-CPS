# Sentinel-CPS eBPF Trace Runbook v0.1.1

This runbook prepares and executes a short eBPF/BCC trace session on the Raspberry Pi Gateway. It collects evidence for Gateway serial observability around `/dev/ttyUSB0`.

## 1. Verify environment

From the Raspberry Pi Gateway:

```bash
cd observability-ebpf/tools
bash check_bcc_environment.sh
```

Review the output for:

- Kernel version
- Python version
- BCC package presence
- Python BCC import status
- tracefs/debugfs status
- sudo/root availability
- `/dev/ttyUSB0` presence
- `sentinel-gateway.service` status

Do not install packages during an evidence run unless you intentionally pause the run and document the change.

## 2. Prepare the Gateway and Hub

```bash
sudo systemctl status sentinel-gateway.service --no-pager
ls -l /dev/ttyUSB0 || ls -l /dev/ttyACM0
```

Open the Gateway dashboard in a browser and confirm `/api/health` responds.

## 3. Run a 60-second trace

From `observability-ebpf/tools/`:

```bash
sudo python3 trace_serial_syscalls_bcc.py \
  --device /dev/ttyUSB0 \
  --duration 60
```

While the tracer is running, use the Gateway dashboard to issue:

1. PING
2. START
3. Wait about 10 seconds
4. STOP
5. RESET

The tracer writes its output under:

```text
observability-ebpf/evidence/VAL-04_Observability/ebpf_traces/
```

## 4. Summarize the trace

Replace the file name with the generated trace file:

```bash
python3 summarize_serial_trace.py \
  --input ../evidence/VAL-04_Observability/ebpf_traces/serial_trace_<timestamp>.csv
```

## 5. Correlate Gateway logs with eBPF trace

```bash
python3 correlate_gateway_logs.py \
  --actions ../../gateway/data/actions.csv \
  --telemetry ../../gateway/data/telemetry.csv \
  --ebpf ../evidence/VAL-04_Observability/ebpf_traces/serial_trace_<timestamp>.csv \
  --window 2.0
```

## 6. Save evidence

Copy these files to private OneDrive:

- `serial_trace_<timestamp>.csv`
- `serial_trace_summary_<timestamp>.csv`
- `gateway_ebpf_correlation_<timestamp>.md`
- screenshots of the dashboard during START/STOP
- terminal screenshot showing the tracer running
- relevant `actions.csv` and `telemetry.csv` copies

## 7. Claim boundary

This run supports VAL-04 evidence collection by showing host-level syscall metadata near the serial chokepoint. It does not by itself validate ESP-NOW/CCMP, physical vehicle movement, or AI anomaly detection.
