#!/usr/bin/env python3
"""
Sentinel-CPS serial syscall tracer v0.1.1.

Read-only BCC tracer for syscall metadata. It traces read/write syscall entry
metadata and resolves fd paths in user space as a best-effort check for a target
serial device such as /dev/ttyUSB0.

Default behavior records only events whose fd path matches the target device.
Use --include-nonmatches to record all read/write events observed during the run.
Serial payload contents are not captured.
"""

from __future__ import annotations

import argparse
import csv
import os
import signal
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

try:
    from bcc import BPF  # type: ignore
except ImportError:
    sys.exit("[ERR] BCC module not found. Install the appropriate python3-bpfcc/bcc package and run on Linux.")

BPF_TEXT = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
    u64 ts_ns;
    u32 pid;
    s32 fd;
    u64 count;
    char comm[TASK_COMM_LEN];
    u8 is_write;
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_read) {
    struct data_t data = {};
    data.ts_ns = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.fd = args->fd;
    data.count = args->count;
    data.is_write = 0;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_write) {
    struct data_t data = {};
    data.ts_ns = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.fd = args->fd;
    data.count = args->count;
    data.is_write = 1;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""

CSV_FIELDS = [
    "timestamp",
    "timestamp_iso",
    "monotonic_ns",
    "pid",
    "comm",
    "syscall",
    "fd",
    "count",
    "retval",
    "fd_path",
    "device_match",
    "notes",
]


def default_output_path() -> str:
    script_dir = Path(__file__).resolve().parent
    base_dir = script_dir.parent
    out_dir = base_dir / "evidence" / "VAL-04_Observability" / "ebpf_traces"
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return str(out_dir / f"serial_trace_{ts}.csv")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Trace read/write syscall metadata with BCC.")
    parser.add_argument("--device", default="/dev/ttyUSB0", help="Target serial device path to match.")
    parser.add_argument("--duration", type=int, default=60, help="Tracing duration in seconds.")
    parser.add_argument("--output", default=None, help="Output CSV path. Defaults to package evidence folder.")
    parser.add_argument("--pid", type=int, default=None, help="Optional user-space PID filter.")
    parser.add_argument("--include-nonmatches", action="store_true", help="Record all read/write events, not only device matches.")
    parser.add_argument("--print-nonmatches", action="store_true", help="Print non-matching events to terminal too. Usually noisy.")
    return parser.parse_args()


def resolve_fd_path(pid: int, fd: int) -> tuple[str, str]:
    try:
        return os.readlink(f"/proc/{pid}/fd/{fd}"), ""
    except FileNotFoundError:
        return "unknown", "FD_PATH_UNKNOWN_OR_CLOSED"
    except PermissionError:
        return "unknown", "FD_PATH_PERMISSION_DENIED"
    except OSError as exc:
        return "unknown", f"FD_PATH_ERROR:{exc.__class__.__name__}"


def comm_to_str(comm) -> str:
    raw = bytes(comm)
    return raw.split(b"\x00", 1)[0].decode("utf-8", "replace")


def main() -> None:
    if os.geteuid() != 0:
        sys.exit("[ERR] This tracer must be run with sudo/root privileges.")

    args = parse_args()
    output = args.output or default_output_path()
    Path(output).parent.mkdir(parents=True, exist_ok=True)

    stop_requested = False

    def handle_signal(signum, frame):  # noqa: ARG001
        nonlocal stop_requested
        stop_requested = True

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    print("[*] Loading BPF program...")
    try:
        bpf = BPF(text=BPF_TEXT)
    except Exception as exc:
        sys.exit(f"[ERR] Failed to load BPF program: {exc}")

    captured_rows = 0
    observed_events = 0
    target_matches = 0

    print(f"[*] Device target: {args.device}")
    print(f"[*] Duration: {args.duration}s")
    print(f"[*] Output: {output}")
    print("[*] Payload capture: disabled")
    print("%-10s %-8s %-14s %-6s %-4s %-8s %s" % ("TIME", "PID", "COMM", "SYS", "FD", "COUNT", "FD_PATH"))

    with open(output, "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=CSV_FIELDS)
        writer.writeheader()

        def on_event(cpu, data, size):  # noqa: ARG001
            nonlocal captured_rows, observed_events, target_matches
            event = bpf["events"].event(data)
            observed_events += 1

            if args.pid is not None and int(event.pid) != args.pid:
                return

            fd_path, notes = resolve_fd_path(int(event.pid), int(event.fd))
            device_match = fd_path == args.device or fd_path.endswith(args.device) or args.device in fd_path
            syscall = "write" if int(event.is_write) else "read"
            comm = comm_to_str(event.comm)
            ts = time.time()

            if device_match:
                target_matches += 1

            if not device_match and not args.include_nonmatches:
                return

            row = {
                "timestamp": f"{ts:.6f}",
                "timestamp_iso": datetime.fromtimestamp(ts).isoformat(),
                "monotonic_ns": str(int(event.ts_ns)),
                "pid": str(int(event.pid)),
                "comm": comm,
                "syscall": syscall,
                "fd": str(int(event.fd)),
                "count": str(int(event.count)),
                "retval": "NOT_CAPTURED_V1",
                "fd_path": fd_path,
                "device_match": str(bool(device_match)),
                "notes": notes,
            }
            writer.writerow(row)
            captured_rows += 1

            if device_match or args.print_nonmatches:
                print("%-10s %-8s %-14s %-6s %-4s %-8s %s" % (
                    datetime.fromtimestamp(ts).strftime("%H:%M:%S"),
                    row["pid"],
                    comm[:14],
                    syscall,
                    row["fd"],
                    row["count"],
                    fd_path,
                ))

        bpf["events"].open_perf_buffer(on_event)
        start = time.time()
        while not stop_requested and (time.time() - start) < args.duration:
            # Timeout is essential; otherwise no events can block past the duration.
            bpf.perf_buffer_poll(timeout=100)
            csv_file.flush()

    print("[*] Trace complete.")
    print(f"[*] Observed events: {observed_events}")
    print(f"[*] Target matches: {target_matches}")
    print(f"[*] CSV rows written: {captured_rows}")
    print(f"[*] Saved: {output}")


if __name__ == "__main__":
    main()
