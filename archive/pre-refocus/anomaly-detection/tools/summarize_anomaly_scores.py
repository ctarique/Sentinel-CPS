#!/usr/bin/env python3
"""Summarize Sentinel-CPS anomaly score CSV output."""

from __future__ import annotations

import argparse
import csv
import os
from collections import Counter
from datetime import datetime
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Summarize Sentinel-CPS anomaly score CSV.")
    parser.add_argument("--input", required=True, help="Path to anomaly_scores_<timestamp>.csv")
    parser.add_argument("--output", help="Optional output CSV path")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if not os.path.exists(args.input):
        raise FileNotFoundError(f"Input not found: {args.input}")

    with open(args.input, "r", newline="", encoding="utf-8", errors="ignore") as f:
        rows = list(csv.DictReader(f))

    total = len(rows)
    scores = []
    for r in rows:
        try:
            scores.append(int(float(r.get("score", 0))))
        except Exception:
            pass

    severity_counts = Counter(r.get("severity", "UNKNOWN") for r in rows)
    rules = sorted(set(r.get("rule_id", "") for r in rows if r.get("rule_id")))

    max_score = max(scores) if scores else 0
    recommended = "OBSERVE_AND_REVIEW"
    if severity_counts.get("HIGH", 0) > 0:
        recommended = "KEEP_OR_PLACE_SYSTEM_IN_STOP_LOCKED_DURING_REVIEW"
    elif severity_counts.get("MEDIUM", 0) > 0:
        recommended = "REVIEW_BEFORE_CONTINUING_PHYSICAL_TEST"

    out_path = Path(args.output) if args.output else Path(args.input).with_name(Path(args.input).name.replace("anomaly_scores_", "anomaly_summary_"))

    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "generated_at",
            "input_file",
            "total_anomalies",
            "max_score",
            "high_severity_count",
            "medium_severity_count",
            "low_severity_count",
            "info_count",
            "triggered_rules",
            "recommended_operator_action",
        ])
        writer.writerow([
            datetime.now().isoformat(timespec="seconds"),
            os.path.abspath(args.input),
            total,
            max_score,
            severity_counts.get("HIGH", 0),
            severity_counts.get("MEDIUM", 0),
            severity_counts.get("LOW", 0),
            severity_counts.get("INFO", 0),
            ";".join(rules),
            recommended,
        ])

    print(f"[*] Summary generated at: {out_path}")


if __name__ == "__main__":
    main()
