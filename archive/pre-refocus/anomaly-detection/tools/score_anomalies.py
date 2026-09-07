#!/usr/bin/env python3
"""
Sentinel-CPS Offline Anomaly Scorer v0.1.1

Reads Gateway actions, telemetry, and eBPF serial trace CSVs and produces
explainable anomaly score rows. This is offline analysis only. It does not
trigger live STOP.
"""

from __future__ import annotations

import argparse
import csv
import os
import sys
from datetime import datetime
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parents[1]
if str(PACKAGE_DIR) not in sys.path:
    sys.path.insert(0, str(PACKAGE_DIR))

from anomaly_engine import (  # noqa: E402
    OUTPUT_FIELDNAMES,
    SourceFiles,
    evaluate_anomalies,
    load_configuration,
)

DEFAULT_OUTPUT_DIR = PACKAGE_DIR / "evidence" / "VAL-05_Threat_Mitigation_Preparation" / "anomaly_scores"
FIELDNAMES = OUTPUT_FIELDNAMES


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Score Sentinel-CPS anomaly rules against CSV logs.")
    parser.add_argument("--actions", required=True, help="Path to Gateway actions.csv")
    parser.add_argument("--telemetry", required=True, help="Path to Gateway telemetry.csv")
    parser.add_argument("--ebpf", required=True, help="Path to eBPF serial_trace.csv")
    parser.add_argument("--config", default=str(PACKAGE_DIR / "config" / "anomaly_rules.example.json"))
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR), help="Directory for anomaly score CSV output")
    return parser.parse_args()


def load_csv(path: str, required: bool = False) -> list[dict[str, str]]:
    if not os.path.exists(path):
        message = f"[WARN] Input file not found: {path}"
        if required:
            raise FileNotFoundError(message)
        print(message)
        return []
    with open(path, "r", newline="", encoding="utf-8", errors="ignore") as input_file:
        return list(csv.DictReader(input_file))


def main() -> None:
    args = parse_args()
    config = load_configuration(args.config)
    actions = load_csv(args.actions)
    telemetry = load_csv(args.telemetry)
    ebpf = load_csv(args.ebpf)

    anomalies = evaluate_anomalies(
        actions,
        telemetry,
        ebpf,
        config,
        SourceFiles(
            actions=os.path.basename(args.actions),
            telemetry=os.path.basename(args.telemetry),
            ebpf=os.path.basename(args.ebpf),
        ),
    )

    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"anomaly_scores_{int(datetime.now().timestamp())}.csv"

    with output_path.open("w", newline="", encoding="utf-8") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(anomalies)

    print("[*] Offline anomaly scoring complete.")
    print(f"[*] Anomalies written: {len(anomalies)}")
    print(f"[*] Output: {output_path}")


if __name__ == "__main__":
    main()
