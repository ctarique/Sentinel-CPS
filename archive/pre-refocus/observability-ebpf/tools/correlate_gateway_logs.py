#!/usr/bin/env python3
"""Correlate Gateway actions/telemetry logs with eBPF serial trace events."""

from __future__ import annotations

import argparse
import csv
import os
from datetime import datetime
from pathlib import Path
from typing import Any


def read_csv(path: str) -> list[dict[str, Any]]:
    if not os.path.exists(path):
        return []
    rows: list[dict[str, Any]] = []
    with open(path, "r", newline="", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    return rows


def row_ts(row: dict[str, Any]) -> float | None:
    try:
        return float(row.get("timestamp", ""))
    except Exception:
        return None


def default_output_path(ebpf_path: str) -> str:
    trace_dir = Path(ebpf_path).resolve().parent
    # If trace is in .../ebpf_traces, sibling correlation_reports is ideal.
    parent = trace_dir.parent if trace_dir.name == "ebpf_traces" else trace_dir
    out_dir = parent / "correlation_reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return str(out_dir / f"gateway_ebpf_correlation_{ts}.md")


def main() -> None:
    parser = argparse.ArgumentParser(description="Correlate Gateway CSV logs with eBPF serial trace events.")
    parser.add_argument("--actions", required=True, help="Path to Gateway data/actions.csv")
    parser.add_argument("--telemetry", required=True, help="Path to Gateway data/telemetry.csv")
    parser.add_argument("--ebpf", required=True, help="Path to serial_trace CSV")
    parser.add_argument("--window", type=float, default=2.0, help="Correlation window in seconds (+/-)")
    parser.add_argument("--output", default=None, help="Optional Markdown output path")
    args = parser.parse_args()

    output = args.output or default_output_path(args.ebpf)
    Path(output).parent.mkdir(parents=True, exist_ok=True)

    actions = read_csv(args.actions)
    telemetry = read_csv(args.telemetry)
    ebpf = read_csv(args.ebpf)

    ebpf_events = []
    for row in ebpf:
        ts = row_ts(row)
        if ts is not None:
            ebpf_events.append((ts, row))

    telemetry_events = []
    for row in telemetry:
        ts = row_ts(row)
        if ts is not None:
            telemetry_events.append((ts, row))

    interesting_commands = {"PING", "START", "STOP", "RESET", "TRACK_UPDATE", "TRACK"}

    with open(output, "w", encoding="utf-8") as out:
        out.write("# Sentinel-CPS Gateway/eBPF Correlation Report\n\n")
        out.write(f"Generated: {datetime.now().isoformat()}\n\n")
        out.write(f"Correlation window: ±{args.window} seconds\n\n")
        out.write("## Inputs\n\n")
        out.write(f"- Actions: `{args.actions}` ({len(actions)} rows loaded)\n")
        out.write(f"- Telemetry: `{args.telemetry}` ({len(telemetry)} rows loaded)\n")
        out.write(f"- eBPF trace: `{args.ebpf}` ({len(ebpf_events)} timestamped rows loaded)\n\n")

        if not actions:
            out.write("## Warning\n\nNo action rows were loaded. Check the actions.csv path.\n")
            print(f"[*] Correlation report generated with warnings: {output}")
            return

        out.write("## Correlated action events\n\n")
        found_interesting = False
        for row in actions:
            ts = row_ts(row)
            if ts is None:
                continue
            cmd = str(row.get("command", ""))
            if cmd not in interesting_commands:
                continue
            found_interesting = True
            dt = datetime.fromtimestamp(ts).isoformat()
            nearby_ebpf = [(e_ts, e) for e_ts, e in ebpf_events if abs(e_ts - ts) <= args.window]
            nearby_tel = [(t_ts, t) for t_ts, t in telemetry_events if abs(t_ts - ts) <= args.window]
            reads = [e for _, e in nearby_ebpf if e.get("syscall") == "read"]
            writes = [e for _, e in nearby_ebpf if e.get("syscall") == "write"]
            bytes_read = sum(int(float(e.get("count", 0) or 0)) for e in reads)
            bytes_written = sum(int(float(e.get("count", 0) or 0)) for e in writes)

            out.write(f"### `{cmd}` at {dt}\n\n")
            out.write(f"- Event ID: `{row.get('event_id', '')}`\n")
            out.write(f"- Result: `{row.get('result', '')}`\n")
            out.write(f"- Nearby eBPF events: {len(nearby_ebpf)}\n")
            out.write(f"  - Reads: {len(reads)} ({bytes_read} bytes requested)\n")
            out.write(f"  - Writes: {len(writes)} ({bytes_written} bytes requested)\n")
            out.write(f"- Nearby telemetry rows: {len(nearby_tel)}\n")

            if nearby_ebpf:
                out.write("\nNearest eBPF rows:\n\n")
                out.write("| delta_s | syscall | comm | fd | count | fd_path |\n")
                out.write("|---:|---|---|---:|---:|---|\n")
                for e_ts, event in sorted(nearby_ebpf, key=lambda item: abs(item[0] - ts))[:10]:
                    out.write(
                        f"| {e_ts - ts:.3f} | {event.get('syscall','')} | {event.get('comm','')} | "
                        f"{event.get('fd','')} | {event.get('count','')} | {event.get('fd_path','')} |\n"
                    )
            out.write("\n")

        if not found_interesting:
            out.write("No PING/START/STOP/RESET/TRACK action rows found.\n")

        out.write("## Interpretation boundary\n\n")
        out.write(
            "This report uses timestamp proximity only. It supports observability evidence and trace correlation, "
            "but it does not prove causality or complete coverage by itself.\n"
        )

    print(f"[*] Correlation report generated: {output}")


if __name__ == "__main__":
    main()
