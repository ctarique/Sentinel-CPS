#!/usr/bin/env python3
"""Summarize Sentinel-CPS serial eBPF trace CSV output."""

from __future__ import annotations

import argparse
import csv
import os
from collections import Counter
from datetime import datetime
from pathlib import Path


def default_output_path(input_path: str) -> str:
    in_path = Path(input_path)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return str(in_path.with_name(f"serial_trace_summary_{ts}.csv"))


def parse_bool(value: str) -> bool:
    return str(value).strip().lower() in {"true", "1", "yes"}


def main() -> None:
    parser = argparse.ArgumentParser(description="Summarize a Sentinel-CPS serial trace CSV.")
    parser.add_argument("--input", required=True, help="Path to serial_trace CSV.")
    parser.add_argument("--output", default=None, help="Optional output summary CSV path.")
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"[ERR] Input file not found: {args.input}")
        return

    output = args.output or default_output_path(args.input)
    Path(output).parent.mkdir(parents=True, exist_ok=True)

    total_reads = 0
    total_writes = 0
    bytes_read = 0
    bytes_written = 0
    target_hits = 0
    process_counts: Counter[str] = Counter()
    first_ts = None
    last_ts = None
    first_iso = ""
    last_iso = ""
    row_count = 0
    malformed_rows = 0

    with open(args.input, "r", newline="", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                ts = float(row.get("timestamp", "0") or 0)
                count = int(float(row.get("count", "0") or 0))
                syscall = row.get("syscall", "")
                comm = row.get("comm", "unknown") or "unknown"
            except Exception:
                malformed_rows += 1
                continue

            row_count += 1
            if first_ts is None or ts < first_ts:
                first_ts = ts
                first_iso = row.get("timestamp_iso", "")
            if last_ts is None or ts > last_ts:
                last_ts = ts
                last_iso = row.get("timestamp_iso", "")

            if parse_bool(row.get("device_match", "False")):
                target_hits += 1

            process_counts[comm] += 1

            if syscall == "read":
                total_reads += 1
                bytes_read += count
            elif syscall == "write":
                total_writes += 1
                bytes_written += count

    duration = (last_ts - first_ts) if first_ts is not None and last_ts is not None else 0.0
    top_processes = ";".join(f"{name}:{count}" for name, count in process_counts.most_common(5))
    notes = f"rows={row_count};malformed_rows={malformed_rows}"

    with open(output, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "source_file",
            "first_timestamp_iso",
            "last_timestamp_iso",
            "duration_sec",
            "total_reads",
            "total_writes",
            "bytes_read",
            "bytes_written",
            "target_device_hits",
            "top_processes",
            "notes",
        ])
        writer.writerow([
            args.input,
            first_iso,
            last_iso,
            f"{duration:.3f}",
            total_reads,
            total_writes,
            bytes_read,
            bytes_written,
            target_hits,
            top_processes,
            notes,
        ])

    print(f"[*] Summary generated: {output}")


if __name__ == "__main__":
    main()
