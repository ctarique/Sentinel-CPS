#!/usr/bin/env python3
"""
Sentinel-CPS Synthetic Log Generator v0.1.1

Creates sample actions, telemetry, and eBPF serial trace logs for offline
anomaly-scoring tests. These logs are synthetic and do not replace lab evidence.
"""

from __future__ import annotations

import csv
import os
import random
import time
from datetime import datetime
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parents[1]
OUT_DIR = PACKAGE_DIR / "sample_data"

ACTIONS_OUT = OUT_DIR / "actions_sample.csv"
TEL_OUT = OUT_DIR / "telemetry_sample.csv"
EBPF_OUT = OUT_DIR / "serial_trace_sample.csv"


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts).isoformat(timespec="milliseconds")


def write_csv(path: Path, header: list[str], rows: list[list[object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(rows)


def main() -> None:
    random.seed(42)
    base_ts = time.time() - 3600

    actions: list[list[object]] = []
    telemetry: list[list[object]] = []
    ebpf: list[list[object]] = []

    # Normal START/RUNNING sequence.
    actions.append([base_ts, "evt_normal_start", "web_ui", "START", "User start", "SUCCESS"])
    ebpf.append([base_ts - 0.05, iso(base_ts - 0.05), 100000001, 1001, "python3", "write", 3, 6, "NOT_CAPTURED_V1", "/dev/ttyUSB0", "True", "START command write"])
    for i in range(5):
        ts = base_ts + i + 0.2
        telemetry.append([ts, "vehicle_01", 3000 + i, 2900 - i, 0.05, "RUNNING", "ttyUSB0"])
        ebpf.append([ts, iso(ts), 100000100 + i, 1001, "python3", "read", 3, 32, "NOT_CAPTURED_V1", "/dev/ttyUSB0", "True", "normal telemetry read"])

    # R001 command burst.
    for i in range(6):
        ts = base_ts + 10 + (i * 0.1)
        actions.append([ts, f"evt_burst_{i}", "web_ui", "TRACK_UPDATE", "fast update", "SUCCESS"])

    # R002 telemetry flood.
    for i in range(15):
        ts = base_ts + 20 + (i * 0.05)
        telemetry.append([ts, "vehicle_01", 3100, 3100, 0.0, "RUNNING", "ttyUSB0"])

    # R003 repeated START/STOP toggling.
    for i, cmd in enumerate(["START", "STOP", "START", "STOP", "START", "STOP"]):
        ts = base_ts + 25 + (i * 1.0)
        actions.append([ts, f"evt_toggle_{i}", "web_ui", cmd, "rapid toggle test", "SUCCESS"])

    # Normal STOP and LOCKED telemetry.
    stop_ts = base_ts + 35
    actions.append([stop_ts, "evt_stop", "web_ui", "STOP", "User stop", "SUCCESS"])
    telemetry.append([stop_ts + 0.2, "vehicle_01", 0, 0, 0.0, "LOCKED", "ttyUSB0"])

    # R004 serial writes after LOCKED grace window.
    for i in range(3):
        ts = stop_ts + 2.0 + i
        ebpf.append([ts, iso(ts), 100002000 + i, 1002, "python3", "write", 3, 8, "NOT_CAPTURED_V1", "/dev/ttyUSB0", "True", "write after locked"])

    # R005 malformed telemetry.
    telemetry.append([base_ts + 45, "vehicle_01", "NaN", "DROP", "ERR", "RUNNING", "ttyUSB0"])

    # R006 orphan serial activity far from actions.
    for i in range(4):
        ts = base_ts + 55 + i * 0.2
        ebpf.append([ts, iso(ts), 100003000 + i, 2222, "rogue_proc", "write", 5, 12, "NOT_CAPTURED_V1", "/dev/ttyUSB0", "True", "no nearby gateway action"])

    # R007 replay-like timing in telemetry.
    replay_start = base_ts + 70
    for i in range(7):
        ts = replay_start + (i * 1.000001)
        telemetry.append([ts, "vehicle_01", 2000, 2000, 0.0, "RUNNING", "ttyUSB0"])

    # Final reset.
    reset_ts = base_ts + 85
    actions.append([reset_ts, "evt_reset", "web_ui", "RESET", "User reset", "SUCCESS"])

    actions.sort(key=lambda r: float(r[0]))
    telemetry.sort(key=lambda r: float(r[0]))
    ebpf.sort(key=lambda r: float(r[0]))

    write_csv(
        ACTIONS_OUT,
        ["timestamp", "event_id", "source", "command", "details", "result"],
        actions,
    )
    write_csv(
        TEL_OUT,
        ["timestamp", "vehicle_id", "adc_l", "adc_r", "steer", "state", "source"],
        telemetry,
    )
    write_csv(
        EBPF_OUT,
        ["timestamp", "timestamp_iso", "monotonic_ns", "pid", "comm", "syscall", "fd", "count", "retval", "fd_path", "device_match", "notes"],
        ebpf,
    )

    print(f"[*] Generated synthetic logs in: {OUT_DIR}")
    print(f"    - {ACTIONS_OUT}")
    print(f"    - {TEL_OUT}")
    print(f"    - {EBPF_OUT}")


if __name__ == "__main__":
    main()
