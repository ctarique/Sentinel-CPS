#!/usr/bin/env python3
"""Manual endpoint test logger for Sentinel-CPS VAL-01."""

import csv
import os
import time
from datetime import datetime

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PACKAGE_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
OUT_DIR = os.path.join(PACKAGE_DIR, "evidence", "VAL-01_Access_Control", "endpoint_port_tests")
RESULTS_CSV = os.path.join(OUT_DIR, "port_test_results.csv")

HEADERS = [
    "timestamp",
    "test_id",
    "endpoint_role",
    "source_device_label",
    "target_host",
    "expected_22",
    "observed_22",
    "expected_8080",
    "observed_8080",
    "evidence_file",
    "notes",
]


def ensure_csv() -> None:
    os.makedirs(OUT_DIR, exist_ok=True)
    if not os.path.exists(RESULTS_CSV):
        with open(RESULTS_CSV, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(HEADERS)


def prompt(label: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    value = input(f"{label}{suffix}: ").strip()
    return value if value else default


def normalize_result(value: str) -> str:
    value = value.strip().upper()
    allowed = {"PASS", "FAIL", "INCONCLUSIVE", "N/A", "NA", "FAIL_OR_FILTERED"}
    if value == "NA":
        return "N/A"
    if value not in allowed:
        return f"UNREVIEWED:{value}" if value else "INCONCLUSIVE"
    return value


def main() -> None:
    print("--- Sentinel-CPS Endpoint Test Logger v0.1.1 ---")
    print("Result labels: PASS, FAIL, FAIL_OR_FILTERED, INCONCLUSIVE, N/A")
    ensure_csv()

    test_id = f"VAL01_{int(time.time())}"
    print(f"Test ID: {test_id}")

    role = prompt("Endpoint role (Admin Laptop / Bastion Host / Smart TV / Unapproved Client / Localhost)", "Admin Laptop")
    device = prompt("Source device label", "Laptop_01")
    target = prompt("Target Gateway host/IP (private; redact before public use)", "<GATEWAY_IP>")
    exp_22 = normalize_result(prompt("Expected Port 22 result", "PASS"))
    obs_22 = normalize_result(prompt("Observed Port 22 result", "INCONCLUSIVE"))
    exp_8080 = normalize_result(prompt("Expected Port 8080 result", "PASS"))
    obs_8080 = normalize_result(prompt("Observed Port 8080 result", "INCONCLUSIVE"))
    evidence_file = prompt("Evidence filename", "")
    notes = prompt("Notes", "")

    row = [
        datetime.now().isoformat(timespec="seconds"),
        test_id,
        role,
        device,
        target,
        exp_22,
        obs_22,
        exp_8080,
        obs_8080,
        evidence_file,
        notes,
    ]

    with open(RESULTS_CSV, "a", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow(row)

    print(f"[*] Logged endpoint result to: {RESULTS_CSV}")


if __name__ == "__main__":
    main()
