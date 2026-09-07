#!/usr/bin/env python3
"""Operator CLI for the separate Sentinel-CPS live anomaly monitor."""

from __future__ import annotations

import argparse
import os
import signal
import sys
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parents[1]
if str(PACKAGE_DIR) not in sys.path:
    sys.path.insert(0, str(PACKAGE_DIR))

from live_anomaly_monitor import (  # noqa: E402
    LiveAnomalyMonitor,
    LiveConfigurationError,
    SchemaError,
    load_live_configuration,
)

TOKEN_ENVIRONMENT_NAME = "SENTINEL_MITIGATION_TOKEN"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Tail bounded Sentinel-CPS CSV state and record durable live incidents."
    )
    parser.add_argument(
        "--config",
        default=str(PACKAGE_DIR / "config" / "live_integration.example.json"),
        help="Secret-free live integration JSON configuration",
    )
    parser.add_argument("--once", action="store_true", help="Process available complete new rows once")
    parser.add_argument(
        "--dry-run", "--fixture-mode", dest="fixture_mode", action="store_true",
        help="Label the run NON_PHYSICAL_FIXTURE and disable Gateway calls",
    )
    parser.add_argument("--validate-config", action="store_true", help="Validate configuration and exit without creating runtime artifacts")
    parser.add_argument("--state-root", help="Override the configured state directory")
    parser.add_argument("--evidence-root", help="Override the configured evidence directory")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    # Read exactly one named environment value. Never print, log, serialize, or
    # pass the value through command-line arguments.
    token = os.environ.get(TOKEN_ENVIRONMENT_NAME)
    token_available = bool(
        token and 32 <= len(token) <= 4096 and token == token.strip()
        and not any(character.isspace() or ord(character) < 32 or ord(character) == 127 for character in token)
    )
    try:
        config = load_live_configuration(
            args.config,
            token_available=token_available,
            state_root=args.state_root,
            evidence_root=args.evidence_root,
        )
    except (OSError, LiveConfigurationError) as exc:
        print(f"[ERROR] Live configuration rejected: {exc}", file=sys.stderr)
        return 2
    if args.validate_config:
        print("[*] Live configuration is valid (secret-free validation output).")
        return 0

    monitor: LiveAnomalyMonitor | None = None
    try:
        monitor = LiveAnomalyMonitor(config, token=token, fixture_mode=args.fixture_mode)

        def request_shutdown(signum: int, frame: object) -> None:
            del signum, frame
            if monitor is not None:
                monitor.request_stop()

        signal.signal(signal.SIGINT, request_shutdown)
        signal.signal(signal.SIGTERM, request_shutdown)
        if args.once:
            anomalies = monitor.process_once()
            print(f"[*] Complete new rows processed once; active rule outputs: {len(anomalies)}")
        else:
            boundary = "NON_PHYSICAL_FIXTURE" if args.fixture_mode else config.response_mode
            print(f"[*] Live anomaly monitor started ({boundary}). Press Ctrl-C to stop.")
            monitor.run()
        if monitor.diagnostics:
            for diagnostic in monitor.diagnostics:
                print(f"[WARN] {diagnostic}", file=sys.stderr)
        monitor.close("COMPLETED")
        return 0
    except SchemaError as exc:
        print(f"[ERROR] Source schema rejected: {exc}", file=sys.stderr)
        if monitor is not None:
            monitor.close("SCHEMA_REJECTED")
        return 3
    except (OSError, LiveConfigurationError) as exc:
        print(f"[ERROR] Monitor stopped safely: {exc}", file=sys.stderr)
        if monitor is not None:
            monitor.close("ERROR")
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
