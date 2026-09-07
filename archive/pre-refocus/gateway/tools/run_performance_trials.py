#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import math
import os
import statistics
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


SOURCE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOURCE_DIR))

from operator_token import (  # noqa: E402
    OPERATOR_TOKEN_REQUIREMENT,
    is_valid_operator_token,
)

OPERATOR_TOKEN = os.environ.get("SENTINEL_OPERATOR_TOKEN")


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def request_json(
    base_url: str,
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
    timeout: float = 5.0,
) -> tuple[int, dict[str, Any], float]:
    body = None
    headers = {}

    if payload is not None:
        if not is_valid_operator_token(OPERATOR_TOKEN):
            raise RuntimeError(
                "SENTINEL_OPERATOR_TOKEN is required for performance commands "
                f"and must contain {OPERATOR_TOKEN_REQUIREMENT}"
            )
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
        headers["X-Sentinel-Operator-Token"] = OPERATOR_TOKEN

    request = urllib.request.Request(
        base_url.rstrip("/") + path,
        data=body,
        headers=headers,
        method=method,
    )

    started_ns = time.perf_counter_ns()

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8")
            status = response.status
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8")
        status = exc.code

    completed_ns = time.perf_counter_ns()
    round_trip_ms = (completed_ns - started_ns) / 1_000_000

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        parsed = {"raw_response": raw}

    return status, parsed, round_trip_ms


def metric_block(values: list[float]) -> dict[str, float | int | None]:
    if not values:
        return {
            "count": 0,
            "minimum_ms": None,
            "mean_ms": None,
            "median_ms": None,
            "p95_ms": None,
            "maximum_ms": None,
        }

    ordered = sorted(values)
    p95_index = max(0, math.ceil(0.95 * len(ordered)) - 1)

    return {
        "count": len(ordered),
        "minimum_ms": round(ordered[0], 6),
        "mean_ms": round(statistics.fmean(ordered), 6),
        "median_ms": round(statistics.median(ordered), 6),
        "p95_ms": round(ordered[p95_index], 6),
        "maximum_ms": round(ordered[-1], 6),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run repeatable Sentinel-CPS Gateway development trials."
    )
    parser.add_argument("--url", default="http://127.0.0.1:8080")
    parser.add_argument("--cycles", type=int, default=30)
    parser.add_argument("--delay", type=float, default=0.03)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--output-dir")
    args = parser.parse_args()

    if args.cycles < 1:
        raise SystemExit("--cycles must be at least 1")

    timestamp = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
    base_dir = Path(__file__).resolve().parents[1]
    output_dir = (
        Path(args.output_dir)
        if args.output_dir
        else base_dir / "evidence" / f"development_{timestamp}"
    )
    output_dir.mkdir(parents=True, exist_ok=True)

    status, health, health_rtt = request_json(
        args.url, "GET", "/api/health", timeout=args.timeout
    )
    if status != 200 or health.get("status") != "ok":
        raise SystemExit(f"Gateway health check failed: HTTP {status}: {health}")

    sequence = [
        ("RESET", "ACKNOWLEDGED", "normal"),
        ("START", "ACKNOWLEDGED", "normal"),
        ("PING", "ACKNOWLEDGED", "normal"),
        ("STATUS", "ACKNOWLEDGED", "normal"),
        ("STOP", "ACKNOWLEDGED", "normal"),
        ("START", "REJECTED_LOCKED", "negative_policy"),
    ]

    rows: list[dict[str, Any]] = []

    for cycle in range(1, args.cycles + 1):
        for command, expected_result, trial_type in sequence:
            status, response, round_trip_ms = request_json(
                args.url,
                "POST",
                "/api/command",
                {"command": command},
                timeout=args.timeout,
            )

            observed_result = str(response.get("result", "MISSING"))
            passed = status == 200 and observed_result == expected_result
            telemetry = response.get("telemetry") or {}

            row = {
                "timestamp_utc": utc_now(),
                "cycle": cycle,
                "source": "USER_PERFORMANCE_TRIAL",
                "trial_type": trial_type,
                "command": command,
                "expected_result": expected_result,
                "observed_result": observed_result,
                "pass": passed,
                "http_status": status,
                "event_id": response.get("event_id", ""),
                "mode": response.get("mode", ""),
                "gateway_processing_ms": response.get(
                    "gateway_processing_ms", ""
                ),
                "ack_latency_ms": response.get("ack_latency_ms", ""),
                "command_total_ms": response.get("command_total_ms", ""),
                "http_round_trip_ms": round(round_trip_ms, 6),
                "vehicle_state": telemetry.get("state", ""),
            }
            rows.append(row)

            marker = "PASS" if passed else "FAIL"
            print(
                f"[{marker}] cycle={cycle:02d} command={command:<5} "
                f"expected={expected_result:<15} observed={observed_result:<15} "
                f"HTTP_RTT={round_trip_ms:.3f} ms"
            )

            if args.delay:
                time.sleep(args.delay)

    trial_csv = output_dir / "trials.csv"
    fieldnames = list(rows[0].keys())

    with trial_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    all_http = [float(row["http_round_trip_ms"]) for row in rows]
    all_gateway = [
        float(row["gateway_processing_ms"])
        for row in rows
        if row["gateway_processing_ms"] != ""
    ]
    all_ack = [
        float(row["ack_latency_ms"])
        for row in rows
        if row["ack_latency_ms"] not in {"", None}
    ]
    all_command_total = [
        float(row["command_total_ms"])
        for row in rows
        if row["command_total_ms"] != ""
    ]

    by_command: dict[str, list[float]] = {}
    for row in rows:
        by_command.setdefault(row["command"], []).append(
            float(row["http_round_trip_ms"])
        )

    passed_count = sum(1 for row in rows if row["pass"])
    total_count = len(rows)

    _, gateway_metrics, metrics_rtt = request_json(
        args.url, "GET", "/api/metrics", timeout=args.timeout
    )

    summary = {
        "generated_utc": utc_now(),
        "environment": "macOS local development using mock Hub transport",
        "measurement_source": "USER_PERFORMANCE_TRIAL",
        "gateway_url": args.url,
        "cycles": args.cycles,
        "total_trials": total_count,
        "passed_trials": passed_count,
        "failed_trials": total_count - passed_count,
        "pass_rate_percent": round(100 * passed_count / total_count, 3),
        "health_check_http_round_trip_ms": round(health_rtt, 6),
        "metrics_endpoint_http_round_trip_ms": round(metrics_rtt, 6),
        "http_round_trip_latency": metric_block(all_http),
        "gateway_processing_latency": metric_block(all_gateway),
        "ack_latency": metric_block(all_ack),
        "command_total_latency": metric_block(all_command_total),
        "http_round_trip_by_command": {
            command: metric_block(values)
            for command, values in sorted(by_command.items())
        },
        "gateway_metrics_snapshot": gateway_metrics,
        "limitations": [
            "Results use the Gateway mock transport on macOS.",
            "HTTP round-trip latency includes the local HTTP request and Flask response.",
            "gateway_processing_ms excludes blocking ACK/NACK wait time.",
            "ack_latency_ms measures dispatch to matching ACK/NACK receipt.",
            "command_total_ms includes the complete command transaction duration.",
            "Automatic keepalive samples are separately labeled AUTO_KEEPALIVE and are excluded from user-command Gateway summaries.",
            "Final thesis performance results require Raspberry Pi, ESP32 Hub, and vehicle testing.",
        ],
    }

    metrics_json = output_dir / "metrics.json"
    metrics_json.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    gateway_snapshot = output_dir / "gateway_metrics_snapshot.json"
    gateway_snapshot.write_text(
        json.dumps(gateway_metrics, indent=2) + "\n",
        encoding="utf-8",
    )

    text_summary = output_dir / "trial-summary.txt"
    text_summary.write_text(
        "\n".join(
            [
                "Sentinel-CPS Gateway Development Trial Summary",
                f"Generated UTC: {summary['generated_utc']}",
                f"Environment: {summary['environment']}",
                f"Cycles: {args.cycles}",
                f"Total trials: {total_count}",
                f"Passed: {passed_count}",
                f"Failed: {total_count - passed_count}",
                f"Pass rate: {summary['pass_rate_percent']}%",
                "",
                "HTTP round-trip latency:",
                json.dumps(summary["http_round_trip_latency"], indent=2),
                "",
                "Gateway processing latency:",
                json.dumps(summary["gateway_processing_latency"], indent=2),
                "",
                "ACK latency:",
                json.dumps(summary["ack_latency"], indent=2),
                "",
                "Command total latency:",
                json.dumps(summary["command_total_latency"], indent=2),
                "",
                "LIMITATION:",
                "These are macOS mock-transport development results, not final "
                "Raspberry Pi or physical ESP32 results.",
                "",
            ]
        ),
        encoding="utf-8",
    )

    print()
    print(f"Trial CSV: {trial_csv}")
    print(f"Metrics JSON: {metrics_json}")
    print(f"Summary: {text_summary}")
    print(f"Pass rate: {summary['pass_rate_percent']}%")

    return 0 if passed_count == total_count else 1


if __name__ == "__main__":
    raise SystemExit(main())
