#!/usr/bin/env python3
"""Validate Sentinel-CPS Gateway deployment configuration."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def fail(message: str) -> None:
    raise SystemExit(f"CONFIG INVALID: {message}")


def require_value(
    config: dict[str, Any],
    key: str,
    expected_type: type,
) -> Any:
    if key not in config:
        fail(f"missing required key: {key}")

    value = config[key]

    if expected_type is int and isinstance(value, bool):
        fail(f"{key} must be an integer")

    if not isinstance(value, expected_type):
        fail(
            f"{key} must be {expected_type.__name__}, "
            f"observed {type(value).__name__}"
        )

    return value


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "config",
        type=Path,
        help="Path to the Gateway JSON configuration",
    )
    args = parser.parse_args()

    try:
        raw = args.config.read_text(encoding="utf-8")
    except FileNotFoundError:
        fail(f"file not found: {args.config}")

    try:
        config = json.loads(raw)
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON: {exc}")

    if not isinstance(config, dict):
        fail("top-level JSON value must be an object")

    host = require_value(config, "host", str)
    port = require_value(config, "port", int)
    mock_serial = require_value(config, "mock_serial", bool)
    serial_port = require_value(config, "serial_port", str)
    serial_baud = require_value(config, "serial_baud", int)
    serial_ack_timeout_ms = require_value(
        config,
        "serial_ack_timeout_ms",
        int,
    )
    mock_ack_delay_ms = require_value(
        config,
        "mock_ack_delay_ms",
        int,
    )
    keepalive_enabled = require_value(
        config,
        "keepalive_enabled",
        bool,
    )
    keepalive_interval_ms = require_value(
        config,
        "keepalive_interval_ms",
        int,
    )
    mitigation_api_enabled = require_value(
        config,
        "mitigation_api_enabled",
        bool,
    )
    mitigation_loopback_only = require_value(
        config,
        "mitigation_loopback_only",
        bool,
    )
    mitigation_cache_size = require_value(
        config,
        "mitigation_idempotency_cache_size",
        int,
    )
    max_points = require_value(
        config,
        "max_centerline_points",
        int,
    )
    safe_boot_locked = require_value(
        config,
        "safe_boot_locked",
        bool,
    )

    if not host.strip():
        fail("host cannot be empty")

    if not 1 <= port <= 65535:
        fail("port must be between 1 and 65535")

    if not serial_port.startswith("/dev/"):
        fail("serial_port must be an absolute /dev path")

    if serial_baud <= 0:
        fail("serial_baud must be positive")

    if serial_ack_timeout_ms <= 0:
        fail("serial_ack_timeout_ms must be positive")

    if mock_ack_delay_ms < 0:
        fail("mock_ack_delay_ms must be zero or positive")

    if keepalive_interval_ms <= 0:
        fail("keepalive_interval_ms must be positive")

    if keepalive_interval_ms >= 7000:
        fail("keepalive_interval_ms must be less than 7000")

    if not mitigation_loopback_only:
        fail(
            "mitigation_loopback_only must remain true for the thesis baseline"
        )

    if not 1 <= mitigation_cache_size <= 1024:
        fail(
            "mitigation_idempotency_cache_size must be between 1 and 1024"
        )

    if not 1 <= max_points <= 10000:
        fail(
            "max_centerline_points must be between 1 and 10000"
        )

    if not safe_boot_locked:
        fail(
            "safe_boot_locked must remain true for deployment"
        )

    mode = "mock" if mock_serial else "hardware"

    print(
        "CONFIG VALID:"
        f" mode={mode}"
        f" host={host}"
        f" port={port}"
        f" serial_port={serial_port}"
        f" serial_baud={serial_baud}"
        f" keepalive_enabled={str(keepalive_enabled).lower()}"
        f" keepalive_interval_ms={keepalive_interval_ms}"
        f" mitigation_api_enabled={str(mitigation_api_enabled).lower()}"
        " mitigation_loopback_only=true"
        f" mitigation_idempotency_cache_size={mitigation_cache_size}"
        " operator_token=required_environment"
        " safe_boot_locked=true"
    )


if __name__ == "__main__":
    main()
